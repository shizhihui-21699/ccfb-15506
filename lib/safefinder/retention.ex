defmodule SafeFinder.Retention do
  @moduledoc """
  Data retention and key rotation: the privacy guarantees have an expiry date.

  Even pseudonymized data becomes sensitive when kept forever. This module
  encodes the deletion policy as pure functions over stored maps/structs, so
  retention is unit-tested rather than assumed from a cron job. In production
  the same functions run inside a periodic task against the real store.

  Policy:

  * Raw sighting detail inside a cluster: pruned to the last
    `sighting_ttl_seconds` (default 7 days); older sightings collapse into
    aggregate counters, so detection continuity survives but detail does not.
  * Fully cold clusters (no sighting for `cold_ttl_seconds`, default 14 days):
    deleted, unless still referenced by an open alert, in which case only the
    minimal alert evidence is retained.
  * HMAC keys: rotated on a schedule. Rotation re-keys live handles and makes
    historical pseudonyms cryptographically unlinkable to new ones; the old
    key is destroyed rather than retained for convenience.
  * Finder ephemeral ids: never stored past the processing of the batch that
    contained them (enforced in `scrub_finder_ids/1`).
  """

  alias SafeFinder.{Hashing, Types}
  alias Types.Cluster

  @default_sighting_ttl 7 * 24 * 60 * 60
  @default_cold_ttl 14 * 24 * 60 * 60

  @doc "Remove finder ephemeral ids from a batch after it has been processed."
  @spec scrub_finder_ids([map()]) :: [map()]
  def scrub_finder_ids(observations) do
    Enum.map(observations, fn obs -> Map.delete(obs, :finder_epid) end)
  end

  @doc """
  Prune per-sighting detail older than the TTL. Aggregate fields
  (`distinct_cells`, counters) are recomputed from what remains so a pruned
  cluster never overstates its evidence.
  """
  @spec prune_cluster(Cluster.t(), integer(), pos_integer()) :: Cluster.t()
  def prune_cluster(%Cluster{} = cluster, now, ttl \\ @default_sighting_ttl) do
    fresh =
      cluster.sightings
      |> Enum.filter(&(&1.at >= now - ttl))
      |> Enum.sort_by(& &1.at)

    unaccompanied = Enum.reject(fresh, & &1.owner_device_present?)
    cells = MapSet.new(unaccompanied, & &1.cell)

    %{
      cluster
      | sightings: fresh,
        distinct_cells: cells,
        unaccompanied_count: length(unaccompanied),
        accompanied_count: length(fresh) - length(unaccompanied),
        first_seen: first_at(fresh),
        last_seen: last_at(fresh)
    }
  end

  @doc """
  Delete clusters that have been cold beyond the TTL. Clusters referenced by
  an open alert are reduced to their alert-evidence skeleton instead of being
  deleted, preserving the victim's timeline without retaining raw sightings.
  """
  @spec sweep_cold(%{term() => Cluster.t()}, MapSet.t(binary()), integer(), pos_integer()) ::
          %{term() => Cluster.t()}
  def sweep_cold(clusters, open_alert_tags, now, ttl \\ @default_cold_ttl) do
    Enum.flat_map(clusters, fn {key, cluster} ->
      cold? = cluster.last_seen != nil and now - cluster.last_seen > ttl
      open? = MapSet.member?(open_alert_tags, cluster.tag_pseudonym)

      cond do
        # cold with no open alert: hard delete
        cold? and not open? -> []
        # cold but still backing an alert: keep a minimal skeleton
        cold? -> [{key, skeleton(cluster)}]
        # still warm: retain unchanged
        true -> [{key, cluster}]
      end
    end)
    |> Map.new()
  end

  @doc """
  Rotate an HMAC key. Returns `{new_key, rekey_fun}` where `rekey_fun/1`
  maps an old handle to its replacement under the new key. The old key is not
  returned and is expected to be dropped by the caller immediately.
  """
  @spec rotate_key(binary()) :: {binary(), (binary() -> binary())}
  def rotate_key(_old_key) do
    new_key = Hashing.new_key()
    # Handles are opaque 128-bit values; under rotation they are replaced by a
    # fresh keyed hash of the old handle, preserving referential equality for
    # in-flight state while severing the link to pre-rotation pseudonyms.
    rekey = fn old_handle -> Hashing.keyed_hash("rekey", old_handle, new_key) end
    {new_key, rekey}
  end

  @doc "Re-key every cluster handle in a store after key rotation."
  @spec rekey_clusters(%{term() => Cluster.t()}, (binary() -> binary())) ::
          %{term() => Cluster.t()}
  def rekey_clusters(clusters, rekey_fun) do
    Map.new(clusters, fn {{victim, tag} = _key, cluster} ->
      new_victim = rekey_fun.(victim)
      new_tag = rekey_fun.(tag)

      {{new_victim, new_tag},
       %{
         cluster
         | victim_pseudonym: new_victim,
           tag_pseudonym: new_tag,
           linked_from: Enum.map(cluster.linked_from, rekey_fun)
       }}
    end)
  end

  defp skeleton(%Cluster{} = cluster) do
    %{
      cluster
      | sightings: [],
        distinct_cells: MapSet.new(),
        unaccompanied_count: 0,
        accompanied_count: 0
    }
  end

  defp first_at([]), do: nil
  defp first_at([s | _]), do: s.at
  defp last_at([]), do: nil
  defp last_at(fresh), do: List.last(fresh).at
end
