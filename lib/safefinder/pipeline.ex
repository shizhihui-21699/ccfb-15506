defmodule SafeFinder.Pipeline do
  @moduledoc """
  The streaming orchestrator: one observation in, at most one alert decision
  out, with every privacy-preserving stage applied in order.

  ```
  observation
     │  pseudonymize + grid-snap (Hashing / GeoCell)
     ▼
  rotation linkage?  ── yes ──▶ inherit predecessor evidence
     │ no
     ▼
  CoMovement.update_cluster / evaluate
     │
     ▼
  Companion.suppression_basis        (family / owner-device)
     │ not suppressed
     ▼
  Alerts.Policy.decide               (dedup, rate limit, supersede)
     │
     ▼
  CrossPlatform.delivery_for         (our app / OS lane / digest)
  ```

  Identity discipline inside the pipeline:

  * Clusters and suspicion state are keyed by **keyed pseudonym handles**,
    never raw BLE addresses, under a key the retention layer rotates.
  * Household attestations are verified against the **raw pseudonyms** the
    victim's phone used to build the signature, then discarded. The raw values
    are never written to the cluster store.
  * Rotation linkage only ever reads cold clusters registered under the same
    victim handle, so cross-victim correlation is structurally impossible.

  This implementation keeps state in-memory behind a `GenServer` so the whole
  system runs and is demoable with zero infrastructure. The public functions
  are shaped exactly like the production boundary: in a real deployment this
  module is replaced by a Kafka/Broadway consumer (or a `PartitionSupervisor`
  of these servers, one per victim-hash partition) while `CoMovement`,
  `Companion`, `Rotation` and `Alerts.Policy` remain unchanged.
  """

  alias SafeFinder.{
    Alerts,
    Companion,
    CoMovement,
    CrossPlatform,
    Crypto,
    GeoCell,
    Hashing,
    Rotation,
    Types
  }

  alias Types.{Cluster, Observation}

  # A tag that has not been seen for this long becomes a "cold cluster" and a
  # candidate predecessor for rotation linkage.
  @cold_after_seconds 45 * 60

  defmodule State do
    @moduledoc false
    defstruct [
      :key,
      :alerts_pid,
      clusters: %{},
      cold: %{},
      safe_list: %{},
      thresholds: nil,
      now_fun: nil
    ]
  end

  use GenServer

  def start_link(opts \\ []) do
    case Keyword.pop(opts, :name) do
      {nil, opts} -> GenServer.start_link(__MODULE__, opts)
      {name, opts} -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @impl true
  def init(opts) do
    alerts_pid =
      case opts[:alerts_pid] do
        # Default to the supervised, registered Alerts process. Tests inject an
        # anonymous pid so they never collide with the application tree.
        nil -> SafeFinder.Alerts
        pid -> pid
      end

    {:ok,
     %State{
       key: opts[:key] || Hashing.new_key(),
       alerts_pid: alerts_pid,
       safe_list: opts[:safe_list] || %{},
       thresholds: opts[:thresholds] || CoMovement.thresholds(),
       now_fun: opts[:now_fun] || fn -> System.system_time(:second) end
     }}
  end

  # --- public API ----------------------------------------------------------

  @doc """
  Ingest one observation. `meta` carries optional `:owner_account`,
  `:owner_device_present?`, `:rssi`, raw-pseudonym household attestation
  material (`:public_pem`, `:attestation`) and a `:victim_profile` used to
  choose the delivery lane. Returns the full processing trace.
  """
  @spec ingest(pid(), Observation.t(), map()) :: map()
  def ingest(pid \\ __MODULE__, %Observation{} = obs, meta \\ %{}) do
    GenServer.call(pid, {:ingest, obs, meta})
  end

  @doc "Register a household public key on the victim's safe list."
  def register_household(pid \\ __MODULE__, public_pem) do
    GenServer.call(pid, {:register_household, public_pem})
  end

  @doc "Current cluster for a raw victim/tag pair (tests/inspection/demo)."
  def cluster(pid \\ __MODULE__, victim_raw, tag_raw) do
    GenServer.call(pid, {:cluster_raw, victim_raw, tag_raw})
  end

  # --- callbacks -----------------------------------------------------------

  @impl true
  def handle_call({:register_household, public_pem}, _from, state) do
    fp = Crypto.fingerprint(public_pem)
    {:reply, fp, %{state | safe_list: Map.put(state.safe_list, fp, public_pem)}}
  end

  @impl true
  def handle_call({:cluster, victim, tag}, _from, state) do
    {:reply, Map.get(state.clusters, {victim, tag}), state}
  end

  @impl true
  def handle_call({:cluster_raw, victim_raw, tag_raw}, _from, state) do
    victim = handle(victim_raw, state.key)
    tag = handle(tag_raw, state.key)
    {:reply, Map.get(state.clusters, {victim, tag}), state}
  end

  @impl true
  def handle_call({:ingest, raw_obs, meta}, _from, state) do
    now = state.now_fun.()

    victim = handle(raw_obs.victim_pseudonym, state.key)
    tag = handle(raw_obs.tag_pseudonym, state.key)
    obs = %{raw_obs | victim_pseudonym: victim, tag_pseudonym: tag}
    key_pair = {victim, tag}

    state = mark_cold_clusters(state, now)

    {rotation_decision, state} = maybe_link(state, obs, meta, now)
    state = upsert_cluster(state, key_pair, obs, rotation_decision, meta)
    cluster = state.clusters[key_pair]

    coords =
      case meta[:coords] do
        nil -> []
        list -> [{obs.lat, obs.lng} | list]
      end

    verdict = CoMovement.evaluate(cluster, now, state.thresholds, coords)

    # Suppression evidence is verified against the *raw* pseudonyms because
    # that is what the victim's phone signed; nothing raw reaches the store.
    evidence = %{
      victim_pseudonym: raw_obs.victim_pseudonym,
      tag_pseudonym: raw_obs.tag_pseudonym,
      public_pem: meta[:public_pem],
      attestation: meta[:attestation]
    }

    suppression =
      Companion.suppression_basis(
        state.safe_list,
        evidence,
        verdict.all_recent_sightings,
        now
      )

    delivery = CrossPlatform.delivery_for(meta[:victim_profile] || %{}, verdict.severity)

    context = %{suppression: suppression, delivery: delivery, rotation: rotation_decision}

    result =
      case Alerts.submit(state.alerts_pid, verdict, context, now) do
        {:issued, alert} ->
          {:issued, alert, CrossPlatform.payload(alert, meta[:payload_opts] || %{})}

        other ->
          other
      end

    trace = %{
      tag: tag,
      victim: victim,
      rotation: rotation_decision,
      severity: verdict.severity,
      confidence: verdict.confidence,
      suppression: suppression,
      result: result
    }

    {:reply, trace, state}
  end

  # --- internals -----------------------------------------------------------

  defp handle(raw, key), do: Hashing.pseudonym_handle(raw, key)

  defp mark_cold_clusters(state, now) do
    cold_after = @cold_after_seconds

    # Register cold summaries but never delete the underlying clusters here:
    # a rotation handover may still need the predecessor's full evidence.
    # Actual deletion is the job of SafeFinder.Retention.
    cold =
      state.clusters
      |> Enum.filter(fn {{_v, _t}, cluster} ->
        cluster.last_seen != nil and now - cluster.last_seen > cold_after and
          cluster.unaccompanied_count > 0
      end)
      |> Enum.reduce(state.cold, fn {{v, t}, cluster}, acc ->
        last = List.last(Enum.sort_by(cluster.sightings, & &1.at))

        summary = %{
          tag_pseudonym: t,
          owner_account: cluster.owner_account,
          victim_pseudonym: v,
          last_cell: last.cell,
          last_cell_coarse: last.coarse_cell,
          last_seen: cluster.last_seen,
          confidence: cluster.confidence,
          accompanied?: cluster.accompanied_count > cluster.unaccompanied_count
        }

        acc
        |> Map.put_new(v, [])
        |> Map.update!(v, fn existing ->
          if Enum.any?(existing, &(&1.tag_pseudonym == t)),
            do: existing,
            else: [summary | existing]
        end)
      end)

    %{state | cold: cold}
  end

  defp maybe_link(state, obs, meta, _now) do
    %{5 => coarse, 7 => fine} = GeoCell.cells(obs.lat, obs.lng, state.key)

    fresh = %{
      tag_pseudonym: obs.tag_pseudonym,
      victim_pseudonym: obs.victim_pseudonym,
      owner_account: meta[:owner_account],
      cell: fine,
      coarse_cell: coarse,
      observed_at: obs.observed_at,
      owner_device_present?: obs.owner_device_present?
    }

    # A new tag may inherit from a fully cold cluster OR from another tag's
    # still-active cluster against the same victim (the fast-swap case). The
    # Rotation policy itself enforces time-gap, accompaniment and victim
    # scoping, so widening the candidate set cannot fuse unrelated tags.
    # `meta.owner_account` is passed in because the fresh tag's own cluster
    # does not exist yet and therefore cannot supply the account itself.
    cold_candidates = Map.get(state.cold, obs.victim_pseudonym, [])
    active_candidates = active_summaries(state, obs.victim_pseudonym, obs.tag_pseudonym)
    candidates = cold_candidates ++ active_candidates

    decision =
      candidates
      |> Enum.map(&Rotation.link(&1, fresh, state.key))
      |> Enum.find(&match?({:linked, _}, &1))

    case decision do
      {:linked, %{predecessor: pred} = info} ->
        state = drop_cold(state, obs.victim_pseudonym, pred)
        {{:linked, info}, stash_predecessor(state, obs.victim_pseudonym, pred)}

      nil ->
        {nil, state}
    end
  end

  defp drop_cold(state, victim, pred_tag) do
    case state.cold do
      %{^victim => list} ->
        %{
          state
          | cold: Map.put(state.cold, victim, Enum.reject(list, &(&1.tag_pseudonym == pred_tag)))
        }

      _ ->
        state
    end
  end

  defp active_summaries(state, victim, new_tag) do
    state.clusters
    |> Enum.filter(fn
      {{v, t}, cluster} when v == victim and t != new_tag ->
        match?(%Cluster{}, cluster) and cluster.unaccompanied_count > 0

      _ ->
        false
    end)
    |> Enum.map(fn {{_v, t}, cluster} ->
      last = cluster.sightings |> Enum.sort_by(& &1.at) |> List.last()

      %{
        tag_pseudonym: t,
        owner_account: cluster.owner_account,
        victim_pseudonym: victim,
        last_cell: last && last.cell,
        last_cell_coarse: last && last.coarse_cell,
        last_seen: cluster.last_seen,
        confidence: cluster.confidence,
        accompanied?: cluster.accompanied_count > cluster.unaccompanied_count
      }
    end)
  end

  defp stash_predecessor(state, victim, pred_tag) do
    case Map.pop(state.clusters, {victim, pred_tag}) do
      {nil, clusters} ->
        %{state | clusters: clusters}

      {pred_cluster, clusters} ->
        %{
          state
          | clusters: Map.put(clusters, {:inherit, victim, pred_tag}, pred_cluster)
        }
    end
  end

  defp upsert_cluster(state, key_pair, obs, rotation_decision, meta) do
    base =
      case Map.get(state.clusters, key_pair) do
        nil -> %Cluster{victim_pseudonym: obs.victim_pseudonym, tag_pseudonym: obs.tag_pseudonym}
        existing -> existing
      end

    {base, state} =
      case rotation_decision do
        {:linked, %{predecessor: pred}} ->
          stash_key = {:inherit, obs.victim_pseudonym, pred}

          case Map.pop(state.clusters, stash_key) do
            {nil, clusters} ->
              {base, %{state | clusters: clusters}}

            {pred_cluster, clusters} ->
              {CoMovement.inherit_evidence(base, pred_cluster), %{state | clusters: clusters}}
          end

        nil ->
          {base, state}
      end

    updated = CoMovement.update_cluster(base, obs, state.key)
    # remember the owner account on the cluster for hard linkage later
    owner_account = meta[:owner_account]
    updated = %{updated | owner_account: owner_account || updated.owner_account}

    %{state | clusters: Map.put(state.clusters, key_pair, updated)}
  end
end
