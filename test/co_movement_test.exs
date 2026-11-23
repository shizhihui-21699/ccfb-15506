defmodule SafeFinder.CoMovementTest do
  use ExUnit.Case, async: true

  alias SafeFinder.{CoMovement, GeoCell, Types}
  alias SafeFinder.Test.Scenario
  alias Types.Cluster

  @grid_key "test-grid-key"

  defp build(observations) do
    Enum.reduce(
      observations,
      %Cluster{
        victim_pseudonym: List.first(observations).victim_pseudonym,
        tag_pseudonym: List.first(observations).tag_pseudonym
      },
      fn obs, acc -> CoMovement.update_cluster(acc, obs, @grid_key) end
    )
  end

  describe "update_cluster" do
    test "unaccompanied sightings accumulate distinct cells and counters" do
      {obs, _} = Scenario.stalking_trip("t", "v", sightings: 5)
      cluster = build(obs)
      assert cluster.unaccompanied_count == 5
      assert cluster.accompanied_count == 0
      assert MapSet.size(cluster.distinct_cells) >= 3
    end

    test "accompanied sightings never contribute unaccompanied evidence" do
      {obs, _} = Scenario.accompanied_trip("t", "v", sightings: 5)
      cluster = build(obs)
      assert cluster.accompanied_count == 5
      assert cluster.unaccompanied_count == 0
      assert MapSet.size(cluster.distinct_cells) == 0
    end

    test "raw coordinates are never retained on the cluster" do
      {obs, _} = Scenario.stalking_trip("t", "v", sightings: 3)
      cluster = build(obs)
      serialized = :erlang.term_to_binary(cluster)
      refute String.contains?(serialized, :erlang.term_to_binary(31.2304))
      assert Enum.all?(cluster.sightings, &is_binary(&1.cell))
    end
  end

  describe "evaluate" do
    test "a sustained multi-location unaccompanied trip reaches :warning" do
      {obs, now} = Scenario.stalking_trip("t", "v", sightings: 8, interval_seconds: 3600)
      verdict = obs |> build() |> CoMovement.evaluate(now)
      assert verdict.severity in [:warning, :critical]
      assert verdict.confidence >= 0.55
      refute verdict.stationary?
    end

    test "a stationary tag is never alerted even after many sightings" do
      {obs, now} = Scenario.stationary_tag("t", "v", sightings: 10)
      verdict = obs |> build() |> CoMovement.evaluate(now)
      assert verdict.severity == :none
      assert verdict.stationary?
    end

    test "a single brief encounter stays below threshold" do
      {obs, now} = Scenario.brief_encounter("t", "v")
      verdict = obs |> build() |> CoMovement.evaluate(now)
      assert verdict.severity == :none
    end

    test "an accompanied trip does not alert" do
      {obs, now} = Scenario.accompanied_trip("t", "v", sightings: 8)
      verdict = obs |> build() |> CoMovement.evaluate(now)
      assert verdict.severity == :none
    end

    test "sightings outside the recency window are ignored" do
      old = Scenario.base_t()
      recent_now = old + 100 * 24 * 60 * 60

      {obs, _} =
        Scenario.stalking_trip("t", "v",
          sightings: 8,
          start_t: old,
          interval_seconds: 3600
        )

      verdict = obs |> build() |> CoMovement.evaluate(recent_now)
      assert verdict.severity == :none
      assert verdict.factors.sighting_count == 0
    end

    test "a long, regular trip scores higher confidence than a short burst" do
      {short, short_now} =
        Scenario.stalking_trip("t", "v", sightings: 4, interval_seconds: 60)

      {long, long_now} =
        Scenario.stalking_trip("t", "v", sightings: 12, interval_seconds: 4 * 3600)

      v_short = CoMovement.evaluate(build(short), short_now)
      v_long = CoMovement.evaluate(build(long), long_now)
      assert v_long.confidence > v_short.confidence
    end
  end

  describe "inherit_evidence (rotation)" do
    test "predecessor evidence carries onto the replacement tag" do
      {obs_a, now_a} = Scenario.stalking_trip("tag-A", "v", sightings: 6)
      pred = build(obs_a)

      {obs_b, now_b} =
        Scenario.stalking_trip("tag-B", "v",
          sightings: 3,
          start_t: now_a + 600,
          interval_seconds: 3600
        )

      succ = build(obs_b)
      merged = CoMovement.inherit_evidence(succ, pred)

      assert merged.tag_pseudonym == "tag-B"
      assert "tag-A" in merged.linked_from
      assert merged.unaccompanied_count == 9
      assert merged.first_seen == pred.first_seen
      verdict = CoMovement.evaluate(merged, now_b)
      assert verdict.severity in [:warning, :critical]
    end
  end

  test "cell ids remain stable through the GeoCell module", _ctx do
    key = @grid_key
    c1 = GeoCell.cell_id(31.23, 121.47, 7, key)
    c2 = GeoCell.cell_id(31.23, 121.47, 7, key)
    assert c1 == c2
  end
end
