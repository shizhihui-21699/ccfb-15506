defmodule SafeFinder.Alerts do
  @moduledoc """
  Alert lifecycle: when a verdict from `SafeFinder.CoMovement` becomes a
  delivered notice, how duplicates and abuse are controlled, and how the same
  detection reaches phones that do not run our app.

  The manager is a `GenServer` keyed by victim pseudonym in production (one
  child per victim partition via a simple hash), but every policy decision is
  delegated to the pure functions in `SafeFinder.Alerts.Policy` so the
  anti-abuse rules are testable without processes.
  """

  alias SafeFinder.Types.Alert

  defmodule State do
    @moduledoc false
    defstruct victims: %{}, counter_seed: 0
  end

  use GenServer

  def start_link(opts \\ []) do
    case Keyword.pop(opts, :name) do
      {nil, opts} -> GenServer.start_link(__MODULE__, opts)
      {name, opts} -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @impl true
  def init(_opts), do: {:ok, %State{}}

  # --- public API ----------------------------------------------------------

  @doc """
  Submit a verdict map (as produced by `CoMovement.evaluate/4`) plus delivery
  context. Returns `{:issued, alert}`, `{:suppressed, reason}` or
  `{:rate_limited, alert}`.
  """
  def submit(pid \\ __MODULE__, verdict, context, now_unix) do
    GenServer.call(pid, {:submit, verdict, context, now_unix})
  end

  @doc "All currently tracked alert records for a victim (tests/inspection)."
  def for_victim(pid \\ __MODULE__, victim_pseudonym) do
    GenServer.call(pid, {:for_victim, victim_pseudonym})
  end

  # --- callbacks -----------------------------------------------------------

  @impl true
  def handle_call({:submit, verdict, context, now}, _from, state) do
    victim = verdict.victim_pseudonym
    history = Map.get(state.victims, victim, [])

    case SafeFinder.Alerts.Policy.decide(verdict, context, history, now) do
      {:suppressed, reason} ->
        {:reply, {:suppressed, reason}, state}

      {:rate_limited, _} ->
        {:reply, {:rate_limited, List.first(history)}, state}

      {:issued, alert} ->
        state = %{state | victims: Map.put(state.victims, victim, [alert | history])}
        {:reply, {:issued, alert}, state}
    end
  end

  @impl true
  def handle_call({:for_victim, victim}, _from, state) do
    {:reply, Map.get(state.victims, victim, []), state}
  end
end

defmodule SafeFinder.Alerts.Policy do
  @moduledoc """
  Pure alert policy. Separated from the GenServer so every abuse vector can be
  exercised directly in tests.

  Abuse controls encoded here:

  * **No owner feedback.** Nothing in an alert, and no API this module offers,
    lets the tag owner learn that an alert fired. Alerts are addressed only to
    victim pseudonyms.
  * **Per-victim rate limits.** A flood of verdicts cannot become a flood of
    notifications; a stalker spamming sightings cannot turn the safety channel
    into a nuisance that gets switched off.
  * **Escalation, not duplication.** Repeated verdicts for the same tag update
    one open alert. A linked rotation supersedes the old alert rather than
    creating a parallel one, preserving a single timeline for the victim.
  * **Suppression gating.** A `:not_suppressed` result from
    `SafeFinder.Companion` is a precondition; suppression reasons are logged
    with the decision.
  """

  alias SafeFinder.Types.Alert

  # at most one new alert per victim per 60 minutes; a critical escalation
  # bypasses the cooldown but is still deduplicated per tag.
  @cooldown_seconds 60 * 60
  # an open alert is automatically considered stale after this and may be
  # replaced rather than updated.
  @open_ttl_seconds 24 * 60 * 60

  @type context :: %{
          required(:suppression) => :not_suppressed | {:suppressed, atom()},
          required(:delivery) => Alert.delivery(),
          optional(:now) => integer(),
          optional(:rotation) => map()
        }

  @spec decide(map(), context(), [Alert.t()], integer()) ::
          {:issued, Alert.t()} | {:suppressed, atom()} | {:rate_limited, Alert.t() | nil}
  def decide(verdict, context, history, now) do
    cond do
      verdict.severity == :none ->
        {:suppressed, :verdict_below_threshold}

      match?({:suppressed, _}, context.suppression) ->
        {:suppressed, elem(context.suppression, 1)}

      true ->
        do_decide(verdict, context, history, now)
    end
  end

  defp do_decide(verdict, context, history, now) do
    same_tag = Enum.find(history, &(&1.tag_pseudonym == verdict.tag_pseudonym))
    recent = Enum.find(history, &(now - &1.issued_at < @cooldown_seconds))
    rotation = context[:rotation]
    predecessor = if rotation, do: find_predecessor(history, rotation), else: nil

    cond do
      # Rotation linkage: new tag, but it carries a predecessor the victim was
      # already warned about. Supersede rather than re-notify from zero.
      predecessor != nil ->
        {:issued, supersede(predecessor, verdict, context, now)}

      # Per-victim cooldown: within one window a non-escalating verdict is
      # rate limited regardless of which tag produced it. A higher severity
      # always breaks through so an escalating situation is never hidden.
      recent != nil and severity_rank(verdict.severity) <= severity_rank(recent.severity) ->
        {:rate_limited, recent}

      # Outside the cooldown, an unchanged-severity repeat for one open tag is
      # deduplicated for the open TTL; a severity escalation still issues.
      same_tag != nil and
        now - same_tag.issued_at < @open_ttl_seconds and
          severity_rank(verdict.severity) <= severity_rank(same_tag.severity) ->
        {:suppressed, :open_alert_for_tag}

      true ->
        issue_new(verdict, context, history, now, recent)
    end
  end

  defp severity_rank(:informational), do: 1
  defp severity_rank(:warning), do: 2
  defp severity_rank(:critical), do: 3

  defp issue_new(verdict, context, _history, now, recent) do
    if recent != nil and verdict.severity != :critical do
      {:rate_limited, recent}
    else
      alert = %Alert{
        alert_id: make_id(verdict, now),
        victim_pseudonym: verdict.victim_pseudonym,
        tag_pseudonym: verdict.tag_pseudonym,
        severity: verdict.severity,
        issued_at: now,
        reason: :persistent_unaccompanied_comovement,
        evidence: %{
          confidence: verdict.confidence,
          factors: verdict.factors,
          linked_from: verdict.linked_from,
          suppression_basis: context.suppression
        },
        delivery: context.delivery
      }

      {:issued, alert}
    end
  end

  defp supersede(%Alert{} = predecessor, verdict, context, now) do
    %Alert{
      predecessor
      | severity: max_severity(predecessor.severity, verdict.severity),
        tag_pseudonym: verdict.tag_pseudonym,
        issued_at: now,
        evidence:
          Map.merge(predecessor.evidence, %{
            confidence: verdict.confidence,
            factors: verdict.factors,
            rotation: context[:rotation],
            prior_tag: predecessor.tag_pseudonym
          }),
        delivery: context.delivery
    }
  end

  defp find_predecessor(history, %{predecessor: tag}) do
    Enum.find(history, &(&1.tag_pseudonym == tag))
  end

  defp find_predecessor(_, _), do: nil

  defp make_id(verdict, now) do
    :crypto.hash(:sha256, [
      "alert",
      verdict.victim_pseudonym,
      verdict.tag_pseudonym,
      Integer.to_string(now)
    ])
    |> Base.encode16(case: :lower)
    |> binary_part(0, 24)
  end

  defp max_severity(:critical, _), do: :critical
  defp max_severity(_, :critical), do: :critical
  defp max_severity(:warning, _), do: :warning
  defp max_severity(_, :warning), do: :warning
  defp max_severity(a, a), do: a
  defp max_severity(a, _), do: a
end
