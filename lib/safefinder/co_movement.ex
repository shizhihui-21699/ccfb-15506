defmodule SafeFinder.CoMovement do
  @moduledoc """
  The detection engine: turns a stream of anonymous sightings into a graded
  suspicion that one unfamiliar tag is persistently travelling with one
  person.

  The engine is intentionally a set of pure functions over `Cluster` state.
  All process machinery (partitioning, timers, persistence) lives in
  `SafeFinder.Pipeline`; this module holds only the decision policy, which is
  where the safety guarantees live and therefore what must be testable.

  ### What counts as suspicious

  A tag is suspicious relative to a victim when it is repeatedly observed
  *unaccompanied by its owner*, across *multiple distinct places*, over a
  *sustained duration*. Each dimension blocks a distinct false-positive class:

  | Dimension            | Blocks                                                            |
  |----------------------|-------------------------------------------------------------------|
  | unaccompanied        | owner with their own tag, family devices (also see `Companion`)   |
  | distinct cells       | a lost tag lying in one spot, a fixed beacon, shared stationary   |
  | sustained duration   | a stranger on one shared commute, brief proximity in a crowd      |
  | repeated sightings   | a single noisy BLE report                                         |

  Confidence is a weighted blend in `[0,1]`; thresholds are configurable and
  documented rather than magic numbers.
  """

  alias SafeFinder.{GeoCell, Types}
  alias Types.{Cluster, Observation}

  @default_thresholds %{
    # minimum unaccompanied sightings before any alert can fire
    min_sightings: 4,
    # minimum distinct level-7 cells (forces genuine travel)
    min_distinct_cells: 3,
    # minimum elapsed seconds from first to last unaccompanied sighting (~2h)
    min_duration_seconds: 2 * 60 * 60,
    # confidence at/above which a warning is raised (mirrors the industry
    # ~10-minute-on-device threshold once sustained travel is established)
    warning_confidence: 0.35,
    # confidence at/above which the alert is treated as critical (~24-48h)
    critical_confidence: 0.80,
    # weight of each component in the confidence blend
    weights: %{duration: 0.35, cells: 0.30, sightings: 0.20, consistency: 0.15},
    # sightings older than this relative to "now" are excluded from evaluation
    recency_window_seconds: 72 * 60 * 60,
    # a tag moving less than this far is considered stationary (lost tag)
    stationary_radius_m: 100.0
  }

  @doc "Return the default policy thresholds (callers may override keys)."
  @spec thresholds() :: map()
  def thresholds, do: @default_thresholds

  @doc """
  Fold one observation into the victim/tag cluster.

  Accompanied sightings are recorded (they feed the companion suppression
  ratio in `SafeFinder.Companion`) but do not grow the unaccompanied evidence.
  Coordinates are converted to cell ids immediately and never retained on the
  cluster.
  """
  @spec update_cluster(Cluster.t(), Observation.t(), binary()) :: Cluster.t()
  def update_cluster(cluster, %Observation{} = obs, grid_key) do
    %{5 => coarse, 7 => fine} = GeoCell.cells(obs.lat, obs.lng, grid_key)

    sighting = %{
      cell: fine,
      coarse_cell: coarse,
      at: obs.observed_at,
      owner_device_present?: obs.owner_device_present?,
      rssi: obs.rssi
    }

    cluster = %{
      cluster
      | sightings: [sighting | cluster.sightings],
        first_seen: min_or(cluster.first_seen, obs.observed_at),
        last_seen: max_or(cluster.last_seen, obs.observed_at)
    }

    if obs.owner_device_present? do
      %{cluster | accompanied_count: cluster.accompanied_count + 1}
    else
      %{
        cluster
        | unaccompanied_count: cluster.unaccompanied_count + 1,
          distinct_cells: MapSet.put(cluster.distinct_cells, fine)
      }
    end
  end

  @doc """
  Evaluate a cluster at time `now_unix` and return a verdict map.

  The map always contains `confidence` and `severity` (`:none |
  :informational | :warning | :critical`) plus the contributing factors, so
  callers and tests can see *why* a decision was reached. Stationary clusters
  (a dropped tag) short-circuit to `:none` regardless of duration.
  """
  @spec evaluate(Cluster.t(), integer(), map(), keyword()) :: map()
  def evaluate(cluster, now_unix, thresholds \\ @default_thresholds, coords \\ []) do
    recent = recent_unaccompanied(cluster, now_unix, thresholds.recency_window_seconds)
    stationary? = stationary?(recent, coords, thresholds.stationary_radius_m)
    factors = confidence_factors(cluster, recent, now_unix, thresholds)
    confidence = blend(factors, thresholds.weights)

    severity =
      cond do
        stationary? -> :none
        not meets_minimums?(recent, factors, thresholds) -> :none
        confidence >= thresholds.critical_confidence -> :critical
        confidence >= thresholds.warning_confidence -> :warning
        confidence > 0.25 -> :informational
        true -> :none
      end

    all_recent = recent_any(cluster, now_unix, thresholds.recency_window_seconds)

    %{
      victim_pseudonym: cluster.victim_pseudonym,
      tag_pseudonym: cluster.tag_pseudonym,
      severity: severity,
      confidence: confidence,
      stationary?: stationary?,
      factors: factors,
      # unaccompanied only - drives suspicion scoring
      recent_sightings: recent,
      # accompanied + unaccompanied - drives the companion suppression check,
      # which must see owner-device presence even when suspicion evidence is empty
      all_recent_sightings: all_recent,
      linked_from: cluster.linked_from
    }
  end

  @doc """
  Merge a predecessor cluster's evidence into a successor after a rotation
  linkage decision (see `SafeFinder.Rotation`). The tag pseudonym changes but
  the victim's accumulated protection carries forward; the predecessor is
  recorded in `linked_from` for audit.
  """
  @spec inherit_evidence(Cluster.t(), Cluster.t()) :: Cluster.t()
  def inherit_evidence(successor, predecessor) do
    %{
      successor
      | sightings: successor.sightings ++ predecessor.sightings,
        distinct_cells: MapSet.union(successor.distinct_cells, predecessor.distinct_cells),
        first_seen: min_or(successor.first_seen, predecessor.first_seen),
        last_seen: max_or(successor.last_seen, predecessor.last_seen),
        unaccompanied_count: successor.unaccompanied_count + predecessor.unaccompanied_count,
        accompanied_count: successor.accompanied_count + predecessor.accompanied_count,
        linked_from: Enum.uniq(predecessor.linked_from ++ [predecessor.tag_pseudonym]),
        confidence: max(successor.confidence, predecessor.confidence)
    }
  end

  # --- scoring internals ---------------------------------------------------

  defp recent_unaccompanied(cluster, now, window) do
    cluster.sightings
    |> Enum.reject(& &1.owner_device_present?)
    |> Enum.filter(&(&1.at >= now - window and &1.at <= now))
    |> Enum.sort_by(& &1.at)
  end

  defp recent_any(cluster, now, window) do
    cluster.sightings
    |> Enum.filter(&(&1.at >= now - window and &1.at <= now))
    |> Enum.sort_by(& &1.at)
  end

  # Coordinates are only available to callers that still hold the original
  # observations (the live pipeline). Persisted clusters carry cells alone,
  # in which case stationarity is approximated by the distinct-cell count.
  defp stationary?(_recent, coords, radius) when is_list(coords) and coords != [] do
    pairs = Enum.map(coords, fn {lat, lng} -> {lat, lng} end)

    if length(pairs) >= 2 do
      {min_lat, max_lat} = pairs |> Enum.map(&elem(&1, 0)) |> Enum.min_max()
      {min_lng, max_lng} = pairs |> Enum.map(&elem(&1, 1)) |> Enum.min_max()

      GeoCell.distance_m({min_lat, min_lng}, {max_lat, max_lng}) < radius
    else
      false
    end
  end

  defp stationary?(recent, _coords, _radius) do
    cells = recent |> Enum.map(& &1.cell) |> MapSet.new()
    MapSet.size(cells) <= 1
  end

  defp meets_minimums?(recent, factors, t) do
    length(recent) >= t.min_sightings and
      factors.distinct_cells >= t.min_distinct_cells and
      factors.duration_seconds >= t.min_duration_seconds
  end

  defp confidence_factors(_cluster, recent, now, t) do
    duration =
      case recent do
        [] -> 0
        _ -> max(0, List.last(recent).at - List.first(recent).at)
      end

    distinct = recent |> Enum.map(& &1.cell) |> MapSet.new() |> MapSet.size()

    # duration saturates at 12 h, cells at 8, sightings at 12.
    %{
      duration_seconds: duration,
      distinct_cells: distinct,
      sighting_count: length(recent),
      duration: min(1.0, duration / (12 * 60 * 60)),
      cells: min(1.0, distinct / 8),
      sightings: min(1.0, length(recent) / 12),
      # regularity: how evenly sightings are spread across the observed span;
      # a tag seen 10 times in 15 minutes then never again scores poorly.
      consistency: consistency(recent, now, t.recency_window_seconds)
    }
  end

  defp consistency([], _now, _window), do: 0.0

  defp consistency(recent, now, window) do
    span = max(1, now - List.first(recent).at)
    # fraction of the observed span actually covered by sighting "patches"
    # (each sighting claims a 10-minute patch, capped at the window).
    patch = 10 * 60

    covered =
      recent
      |> Enum.map(&{max(0, &1.at - patch), min(now, &1.at + patch)})
      |> Enum.sort()
      |> merge_intervals()
      |> Enum.reduce(0, fn {a, b}, acc -> acc + (b - a) end)

    min(1.0, covered / min(span, window))
  end

  defp merge_intervals([]), do: []

  defp merge_intervals([first | rest]) do
    Enum.reduce(rest, [first], fn {a, b}, [{pa, pb} | _] = acc ->
      if a <= pb do
        [{pa, max(pb, b)} | tl(acc)]
      else
        [{a, b} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp blend(factors, weights) do
    weights.duration * factors.duration +
      weights.cells * factors.cells +
      weights.sightings * factors.sightings +
      weights.consistency * factors.consistency
  end

  defp min_or(nil, b), do: b
  defp min_or(a, b), do: min(a, b)
  defp max_or(nil, b), do: b
  defp max_or(a, b), do: max(a, b)
end
