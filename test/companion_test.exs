defmodule SafeFinder.CompanionTest do
  use ExUnit.Case, async: true

  alias SafeFinder.{Companion, Crypto}

  describe "owner_accompanied?" do
    test "requires a strong majority of accompanied sightings" do
      sightings = for _ <- 1..8, do: %{owner_device_present?: true}
      sightings = sightings ++ for(_ <- 1..2, do: %{owner_device_present?: false})
      assert Companion.owner_accompanied?(sightings)
    end

    test "a single accompanied sighting never suppresses" do
      # 1/1 accompanied is technically 100% but the guard against a stalker
      # briefly passing the owner is enforced via a minimum sample size.
      refute Companion.owner_accompanied?([%{owner_device_present?: true}], 0.8)
      # and below the sample floor even a majority cannot suppress
      refute Companion.owner_accompanied?(
               [
                 %{owner_device_present?: true},
                 %{owner_device_present?: true},
                 %{owner_device_present?: false}
               ],
               0.8
             )
    end

    test "empty history is not accompanied" do
      refute Companion.owner_accompanied?([])
    end

    test "a stalker briefly passing the owner does not clear the signal" do
      sightings =
        for(_ <- 1..9, do: %{owner_device_present?: false}) ++
          [%{owner_device_present?: true}]

      refute Companion.owner_accompanied?(sightings)
    end
  end

  describe "suppression_basis" do
    setup do
      {pub, priv} = Crypto.generate_keypair()
      now = 5_000
      att = Crypto.attest(priv, "v1", "t1", now)
      safe_list = %{Crypto.fingerprint(pub) => pub}

      %{pub: pub, att: att, safe_list: safe_list, now: now}
    end

    test "household attestation suppresses the exact pair only", ctx do
      evidence = %{
        victim_pseudonym: "v1",
        tag_pseudonym: "t1",
        public_pem: ctx.pub,
        attestation: ctx.att
      }

      assert {:suppressed, :household_attestation} =
               Companion.suppression_basis(ctx.safe_list, evidence, [], ctx.now)

      # same proof presented for a different tag fails closed
      other = %{evidence | tag_pseudonym: "t2"}

      assert :not_suppressed =
               Companion.suppression_basis(ctx.safe_list, other, [], ctx.now)
    end

    test "an unregistered household key is not trusted", ctx do
      evidence = %{
        victim_pseudonym: "v1",
        tag_pseudonym: "t1",
        public_pem: ctx.pub,
        attestation: ctx.att
      }

      assert :not_suppressed =
               Companion.suppression_basis(%{}, evidence, [], ctx.now)
    end

    test "owner-device presence takes precedence and needs no attestation" do
      sightings = for _ <- 1..10, do: %{owner_device_present?: true}

      assert {:suppressed, :owner_device_present} =
               Companion.suppression_basis(%{}, %{}, sightings, 0)
    end
  end
end
