defmodule SafeFinder.Rotation do
  @moduledoc """
  Defeating tag rotation: linking a suspicious tag to its replacement without
  turning the backend into a global tag-tracking database.

  A stalker who knows detection exists will swap tags every few days, so no
  single `(victim, tag)` cluster ever crosses the alert threshold. Two linkage
  mechanisms, with very different privacy postures, are composed:

  ### Hard linkage (account-side, owner-authorizable)

  Tags are registered to an owner account. When several *different* tags
  registered to the **same owner account** each build a co-movement cluster
  against the same victim in quick succession, the clusters are linked. The
  backend already needs the owner account for the legitimate lost-and-found
  flow, so this adds no new identifier. Linkage is confined to the
  victim-scoped suspicion table and never produces an owner location history.

  ### Soft linkage (spatiotemporal continuity, victim-scoped)

  When tag A's last sighting near a victim and tag B's first sighting near the
  same victim are close in time and coincide in the privacy grid, and no owner
  device accompanied the handover, B is treated as a probable continuation of
  A *for that victim only*. Spatial continuity is evaluated purely on grid
  cells - a cold cluster stores no coordinates - so linkage never reconstructs
  a path. The linkage key is derived from the victim pseudonym, so the same
  two tags cannot be correlated across different people. Probability is
  deliberately conservative to avoid fusing unrelated tags that merely share a
  busy train.

  Everything here is pure and side-effect free so the policy is exhaustively
  testable.
  """

  @typedoc "A cluster summary at the moment it went cold (tag stopped appearing)."
  @type cold_cluster :: %{
          tag_pseudonym: binary(),
          owner_account: binary() | nil,
          victim_pseudonym: binary(),
          last_cell: binary(),
          last_cell_coarse: binary(),
          last_seen: integer(),
          confidence: float(),
          accompanied?: boolean()
        }

  @typedoc "The first sighting of a newly seen tag against the same victim."
  @type fresh_sighting :: %{
          tag_pseudonym: binary(),
          owner_account: binary() | nil,
          victim_pseudonym: binary(),
          cell: binary(),
          coarse_cell: binary(),
          observed_at: integer(),
          owner_device_present?: boolean()
        }

  @doc """
  Hard-link probability: 1.0 when both tags share an owner account and both
  were unaccompanied, otherwise 0.0. A shared account with owner presence is
  treated as benign (the owner is simply using several of their own tags).
  """
  @spec hard_link_prob(cold_cluster(), fresh_sighting()) :: float()
  def hard_link_prob(cold, fresh) do
    same_victim? = cold.victim_pseudonym == fresh.victim_pseudonym
    same_owner? = cold.owner_account != nil and cold.owner_account == fresh.owner_account
    unaccompanied? = not cold.accompanied? and not fresh.owner_device_present?

    if same_victim? and same_owner? and unaccompanied?, do: 1.0, else: 0.0
  end

  @doc """
  Soft-link probability from spatiotemporal continuity.

  Returns a value in `[0.0, 0.7]` (capped below certainty) based on the time
  gap and the grid-cell relationship of the handover, or 0.0 if the time gap
  exceeds the cut-off, the cells do not meet at neighbourhood level, or an
  owner device accompanied either side. A victim-scoped linkage seed mixes the
  victim pseudonym into every derived id so continuity cannot be evaluated
  across victims.
  """
  @spec soft_link_prob(cold_cluster(), fresh_sighting(), integer()) :: float()
  def soft_link_prob(cold, fresh, _grid_key, max_gap_seconds \\ 1800) do
    cond do
      cold.victim_pseudonym != fresh.victim_pseudonym ->
        0.0

      cold.accompanied? or fresh.owner_device_present? ->
        0.0

      fresh.observed_at < cold.last_seen ->
        0.0

      fresh.observed_at - cold.last_seen > max_gap_seconds ->
        0.0

      true ->
        space_score = cell_relationship_score(cold, fresh)

        # No neighbourhood overlap at all: the tags cannot be a continuation.
        if space_score == 0.0 do
          0.0
        else
          time_score = 1.0 - (fresh.observed_at - cold.last_seen) / max_gap_seconds
          min(0.7, 0.5 * time_score + 0.5 * space_score)
        end
    end
  end

  # Same ~150 m cell: strong spatial continuity.
  defp cell_relationship_score(%{last_cell: c}, %{cell: c}), do: 1.0

  # Only the ~1.2 km neighbourhood matches (fine cells genuinely differ):
  # weak continuity.
  defp cell_relationship_score(
         %{last_cell: fc, last_cell_coarse: cc},
         %{cell: fnc, coarse_cell: cc}
       )
       when fc != fnc,
       do: 0.5

  defp cell_relationship_score(_, _), do: 0.0

  @doc """
  Combined decision. Hard linkage wins outright; otherwise soft linkage must
  clear a confidence floor (default 0.55). Returns either
  `{:linked, %{basis: :hard | :soft, probability: float}}` or `:no_link`.
  """
  @spec link(cold_cluster(), fresh_sighting(), integer(), float()) ::
          {:linked, map()} | :no_link
  def link(cold, fresh, grid_key, soft_floor \\ 0.55) do
    hard = hard_link_prob(cold, fresh)
    soft = soft_link_prob(cold, fresh, grid_key)

    cond do
      hard == 1.0 ->
        {:linked, %{basis: :hard, probability: 1.0, predecessor: cold.tag_pseudonym}}

      soft >= soft_floor ->
        {:linked, %{basis: :soft, probability: soft, predecessor: cold.tag_pseudonym}}

      true ->
        :no_link
    end
  end

  @doc """
  Victim-scoped linkage seed. Even with database read access, an operator
  cannot tell whether two seeds observed under different victim pseudonyms
  refer to the same physical handover.
  """
  @spec linkage_seed(binary(), binary(), binary()) :: binary()
  def linkage_seed(victim_pseudonym, predecessor_tag, key) do
    SafeFinder.Hashing.keyed_hash(
      "link:#{victim_pseudonym}",
      predecessor_tag,
      key
    )
  end
end
