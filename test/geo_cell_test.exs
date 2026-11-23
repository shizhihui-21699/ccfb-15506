defmodule SafeFinder.GeoCellTest do
  use ExUnit.Case, async: true
  doctest SafeFinder.GeoCell

  alias SafeFinder.GeoCell

  test "same coordinate produces identical cell ids at a level" do
    key = "grid-secret"

    assert GeoCell.cell_id(31.23, 121.47, 7, key) ==
             GeoCell.cell_id(31.23, 121.47, 7, key)
  end

  test "different grid keys produce unrelated cell ids" do
    refute GeoCell.cell_id(31.23, 121.47, 7, "k1") ==
             GeoCell.cell_id(31.23, 121.47, 7, "k2")
  end

  test "nearby coordinates share a level-7 cell, distant ones do not" do
    key = "grid-secret"
    # ~30 m apart: same ~150 m cell
    a = GeoCell.cell_id(31.23000, 121.47000, 7, key)
    b = GeoCell.cell_id(31.23027, 121.47000, 7, key)
    assert a == b

    # several km apart: different fine cells
    c = GeoCell.cell_id(31.26000, 121.50000, 7, key)
    refute a == c
  end

  test "haversine distance is symmetric and zero for identical points" do
    p = {31.23, 121.47}
    assert GeoCell.distance_m(p, p) == 0.0

    assert_in_delta GeoCell.distance_m(p, {31.231, 121.47}),
                    GeoCell.distance_m({31.231, 121.47}, p),
                    0.001
  end

  test "one degree of latitude is roughly 111 km" do
    d = GeoCell.distance_m({0.0, 0.0}, {1.0, 0.0})
    assert_in_delta d, 111_195.0, 200.0
  end
end

defmodule SafeFinder.HashingTest do
  use ExUnit.Case, async: true

  alias SafeFinder.Hashing

  test "keyed hash is deterministic and key-sensitive" do
    h1 = Hashing.keyed_hash("ns", "v", "key-a")
    h2 = Hashing.keyed_hash("ns", "v", "key-a")
    h3 = Hashing.keyed_hash("ns", "v", "key-b")
    assert h1 == h2
    refute h1 == h3
    assert byte_size(h1) == 16
  end

  test "pseudonym handles are namespaced and do not leak the raw pseudonym" do
    raw = <<0xAA, 0xBB>>
    handle = Hashing.pseudonym_handle(raw, "k")
    refute String.contains?(Base.encode16(handle), "AABB")
    assert Hashing.pseudonym_handle(raw, "k") == handle
  end
end
