defmodule SafeFinder.Alerts.PolicyTest do
  use ExUnit.Case, async: true

  alias SafeFinder.Alerts.Policy
  alias SafeFinder.Types.Alert

  @cooldown 60 * 60

  defp verdict(severity, confidence, victim \\ "v", tag \\ "t", linked \\ []) do
    %{
      victim_pseudonym: victim,
      tag_pseudonym: tag,
      severity: severity,
      confidence: confidence,
      stationary?: false,
      factors: %{duration_seconds: 10_000, distinct_cells: 5, sighting_count: 8},
      recent_sightings: [],
      linked_from: linked
    }
  end

  defp ctx(overrides \\ %{}) do
    Map.merge(%{suppression: :not_suppressed, delivery: :app_push}, overrides)
  end

  test "a :none severity is never issued" do
    assert {:suppressed, :verdict_below_threshold} =
             Policy.decide(verdict(:none, 0.1), ctx(), [], 1_000)
  end

  test "a suppressed verdict never becomes an alert" do
    assert {:suppressed, :owner_device_present} =
             Policy.decide(
               verdict(:critical, 0.9),
               ctx(%{suppression: {:suppressed, :owner_device_present}}),
               [],
               1_000
             )
  end

  test "the first qualifying warning is issued" do
    assert {:issued, %Alert{severity: :warning, delivery: :app_push}} =
             Policy.decide(verdict(:warning, 0.6), ctx(), [], 1_000)
  end

  test "a second verdict inside the cooldown is rate limited" do
    {:issued, first} = Policy.decide(verdict(:warning, 0.6), ctx(), [], 1_000)

    assert {:rate_limited, ^first} =
             Policy.decide(verdict(:warning, 0.65), ctx(), [first], 1_500)
  end

  test "a critical escalation bypasses the cooldown" do
    {:issued, first} = Policy.decide(verdict(:warning, 0.6), ctx(), [], 1_000)

    assert {:issued, %Alert{severity: :critical}} =
             Policy.decide(verdict(:critical, 0.9), ctx(), [first], 1_500)
  end

  test "a second verdict for the same open tag outside the cooldown but inside the open TTL is deduplicated" do
    {:issued, first} = Policy.decide(verdict(:warning, 0.6), ctx(), [], 1_000)

    assert {:suppressed, :open_alert_for_tag} =
             Policy.decide(verdict(:warning, 0.7), ctx(), [first], 1_000 + @cooldown + 60)
  end

  test "a severity escalation for an open tag bypasses both cooldown and TTL" do
    {:issued, first} = Policy.decide(verdict(:warning, 0.6), ctx(), [], 1_000)

    assert {:issued, %Alert{severity: :critical}} =
             Policy.decide(verdict(:critical, 0.9), ctx(), [first], 1_000 + 60)
  end

  test "a rotated tag supersedes the predecessor alert instead of duplicating" do
    {:issued, first} =
      Policy.decide(verdict(:warning, 0.6, "v", "tag-A"), ctx(), [], 1_000)

    rotation = %{basis: :hard, probability: 1.0, predecessor: "tag-A"}

    assert {:issued, %Alert{} = merged} =
             Policy.decide(
               verdict(:warning, 0.7, "v", "tag-B"),
               ctx(%{rotation: rotation}),
               [first],
               2_000
             )

    assert merged.tag_pseudonym == "tag-B"
    assert merged.evidence.prior_tag == "tag-A"
    assert merged.evidence.rotation == rotation
  end

  test "rotation without a known predecessor still issues a fresh alert" do
    rotation = %{basis: :soft, probability: 0.6, predecessor: "unknown-tag"}

    assert {:issued, %Alert{tag_pseudonym: "tag-C"}} =
             Policy.decide(
               verdict(:warning, 0.6, "v", "tag-C"),
               ctx(%{rotation: rotation}),
               [],
               2_000
             )
  end
end

defmodule SafeFinder.CrossPlatformTest do
  use ExUnit.Case, async: true

  alias SafeFinder.{CrossPlatform, Types}
  alias Types.Alert

  test "app users get push, non-app warning uses the platform lane" do
    assert CrossPlatform.delivery_for(%{app_installed?: true}, :warning) == :app_push
    assert CrossPlatform.delivery_for(%{app_installed?: false}, :warning) == :platform_payload
  end

  test "non-app informational notices are batched into a digest" do
    assert CrossPlatform.delivery_for(%{app_installed?: false}, :informational) ==
             :delayed_digest
  end

  test "the payload never carries an owner identity or precise locations" do
    alert = %Alert{
      alert_id: "a1",
      victim_pseudonym: "v",
      tag_pseudonym: "t",
      severity: :critical,
      issued_at: 1_000,
      reason: :x,
      evidence: %{confidence: 0.9, factors: %{duration_seconds: 7200}},
      delivery: :platform_payload
    }

    payload = CrossPlatform.payload(alert)
    assert payload.owner == nil
    assert payload.precise_locations == nil
    assert payload.timeline.confidence_band == :high
    assert String.starts_with?(payload.tag.instruction_url, "https://safety.example/")
  end
end
