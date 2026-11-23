defmodule SafeFinder.RotationTest do
  use ExUnit.Case, async: true

  alias SafeFinder.Rotation

  defp cold(overrides \\ %{}) do
    Map.merge(
      %{
        tag_pseudonym: "tag-A",
        owner_account: "acct-7",
        victim_pseudonym: "victim-9",
        last_cell: "fine-cell",
        last_cell_coarse: "coarse-cell",
        last_seen: 10_000,
        confidence: 0.7,
        accompanied?: false
      },
      overrides
    )
  end

  defp fresh(overrides \\ %{}) do
    Map.merge(
      %{
        tag_pseudonym: "tag-B",
        owner_account: "acct-7",
        victim_pseudonym: "victim-9",
        cell: "fine-cell",
        coarse_cell: "coarse-cell",
        observed_at: 10_600,
        owner_device_present?: false
      },
      overrides
    )
  end

  describe "hard_link_prob" do
    test "same owner account, same victim, unaccompanied -> certain link" do
      assert Rotation.hard_link_prob(cold(), fresh()) == 1.0
    end

    test "different victim pseudonyms never link" do
      assert Rotation.hard_link_prob(cold(), fresh(%{victim_pseudonym: "other"})) == 0.0
    end

    test "different owner accounts do not hard-link" do
      assert Rotation.hard_link_prob(cold(), fresh(%{owner_account: "acct-99"})) == 0.0
    end

    test "owner presence on either side breaks the link (benign multi-tag use)" do
      assert Rotation.hard_link_prob(cold(%{accompanied?: true}), fresh()) == 0.0

      assert Rotation.hard_link_prob(
               cold(),
               fresh(%{owner_device_present?: true})
             ) == 0.0
    end
  end

  describe "soft_link_prob" do
    test "same fine cell within the time window gives a strong score" do
      prob = Rotation.soft_link_prob(cold(), fresh(), 1)
      assert prob >= 0.55
      assert prob <= 0.7
    end

    test "only a coarse-cell match scores lower and can fall below the floor" do
      # make the time gap near the maximum so the blended score stays under
      # the soft-link floor despite the weak neighbourhood-only match
      prob =
        Rotation.soft_link_prob(
          cold(%{last_cell: "different-fine"}),
          fresh(%{observed_at: 10_000 + 1700}),
          1
        )

      assert prob < 0.55
      assert prob > 0.0
    end

    test "a handover beyond the time gap is not linked" do
      assert Rotation.soft_link_prob(cold(), fresh(%{observed_at: 10_000 + 3600}), 1) ==
               0.0
    end

    test "a tag handed over in a different neighbourhood is not linked" do
      assert Rotation.soft_link_prob(
               cold(%{last_cell: "x", last_cell_coarse: "far"}),
               fresh(%{cell: "y", coarse_cell: "away"}),
               1
             ) == 0.0
    end

    test "victim scoping: identical handover under another victim is unlinkable" do
      key = "k"
      seed1 = Rotation.linkage_seed("victim-9", "tag-A", key)
      seed2 = Rotation.linkage_seed("victim-3", "tag-A", key)
      refute seed1 == seed2
    end
  end

  describe "link/4" do
    test "hard linkage wins even when spatial evidence is weak" do
      weak_fresh = fresh(%{cell: "elsewhere", coarse_cell: "far-away"})
      assert {:linked, %{basis: :hard}} = Rotation.link(cold(), weak_fresh, 1)
    end

    test "soft linkage above the floor links without a shared account" do
      no_account = fresh(%{owner_account: nil})
      assert {:linked, %{basis: :soft}} = Rotation.link(cold(), no_account, 1)
    end

    test "no link when both mechanisms fail" do
      result =
        Rotation.link(
          cold(%{owner_account: nil, last_cell: "x", last_cell_coarse: "far"}),
          fresh(%{
            owner_account: nil,
            cell: "y",
            coarse_cell: "away",
            observed_at: 10_000 + 3600
          }),
          1
        )

      assert result == :no_link
    end
  end
end
