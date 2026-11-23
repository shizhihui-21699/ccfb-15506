defmodule SafeFinder.RetentionTest do
  use ExUnit.Case, async: true

  alias SafeFinder.{Retention, Types}
  alias Types.Cluster

  defp cluster_with_sightings do
    sightings =
      for i <- 0..9 do
        %{
          cell: "cell-#{rem(i, 4)}",
          coarse_cell: "coarse",
          at: 10_000 + i * 1000,
          owner_device_present?: rem(i, 5) == 0,
          rssi: -60
        }
      end

    %Cluster{
      victim_pseudonym: "v",
      tag_pseudonym: "t",
      sightings: sightings,
      distinct_cells: MapSet.new(sightings, & &1.cell),
      first_seen: 10_000,
      last_seen: 19_000,
      accompanied_count: 2,
      unaccompanied_count: 8
    }
  end

  test "scrub_finder_ids removes relayer identity after batch processing" do
    batch = [%{finder_epid: "ep1", x: 1}, %{finder_epid: "ep2", x: 2}]
    scrubbed = Retention.scrub_finder_ids(batch)
    refute Enum.any?(scrubbed, &Map.has_key?(&1, :finder_epid))
  end

  test "prune_cluster drops old detail and recomputes aggregates" do
    now = 15_500
    pruned = Retention.prune_cluster(cluster_with_sightings(), now, 5_000)

    assert Enum.all?(pruned.sightings, &(&1.at >= now - 5_000))

    assert pruned.unaccompanied_count ==
             length(Enum.reject(pruned.sightings, & &1.owner_device_present?))

    assert MapSet.size(pruned.distinct_cells) <= 4
  end

  test "sweep_cold deletes clusters beyond the cold TTL" do
    now = 2_000_000
    ttl = 100_000

    cold = %{cluster_with_sightings() | tag_pseudonym: "cold-tag"}
    warm = %{cluster_with_sightings() | tag_pseudonym: "warm-tag", last_seen: now - 1_000}

    kept =
      Retention.sweep_cold(
        %{{"v", "cold-tag"} => cold, {"v", "warm-tag"} => warm},
        MapSet.new(),
        now,
        ttl
      )

    refute Map.has_key?(kept, {"v", "cold-tag"})
    assert Map.has_key?(kept, {"v", "warm-tag"})
  end

  test "clusters backing an open alert are skeletonized, not deleted" do
    cluster = %{cluster_with_sightings() | tag_pseudonym: "alert-tag"}

    kept =
      Retention.sweep_cold(
        %{{"v", "alert-tag"} => cluster},
        MapSet.new(["alert-tag"]),
        2_000_000,
        100_000
      )

    skeleton = Map.fetch!(kept, {"v", "alert-tag"})
    assert skeleton.sightings == []
    assert skeleton.unaccompanied_count == 0
    assert skeleton.tag_pseudonym == "alert-tag"
  end

  test "key rotation severs linkability while preserving referential structure" do
    clusters = %{
      {"v1", "t1"} => %Cluster{
        victim_pseudonym: "v1",
        tag_pseudonym: "t1",
        linked_from: ["old-tag"]
      }
    }

    {new_key, rekey} = Retention.rotate_key("old-key")
    assert is_binary(new_key) and byte_size(new_key) == 32

    rekeyed = Retention.rekey_clusters(clusters, rekey)
    assert Map.has_key?(rekeyed, {rekey.("v1"), rekey.("t1")})

    {_, updated} = Enum.at(rekeyed, 0)
    assert updated.linked_from == [rekey.("old-tag")]
  end
end
