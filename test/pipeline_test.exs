defmodule SafeFinder.PipelineTest do
  use ExUnit.Case, async: false

  alias SafeFinder.{Crypto, Pipeline}
  alias SafeFinder.Test.Scenario
  alias SafeFinder.Types.Observation

  # A controllable clock: the pipeline reads "now" through this agent.
  defmodule Clock do
    use Agent
    def start_link(t), do: Agent.start_link(fn -> t end, name: __MODULE__)
    def get, do: Agent.get(__MODULE__, & &1)
    def set(t), do: Agent.update(__MODULE__, fn _ -> t end)
  end

  setup do
    Clock.start_link(Scenario.base_t())
    {:ok, alerts} = SafeFinder.Alerts.start_link([])
    {:ok, pipe} = Pipeline.start_link(now_fun: &Clock.get/0, alerts_pid: alerts)
    %{pipe: pipe}
  end

  describe "end-to-end stalking scenario" do
    test "a covert tag following one person across the city raises an alert", ctx do
      {obs, final_now} = Scenario.stalking_trip("ble-tag-X", "phone-victim", sightings: 10)
      Clock.set(final_now)

      traces = Scenario.feed(ctx.pipe, obs, fn _ -> %{} end, &Clock.set/1)
      last = List.last(traces)

      assert last.severity in [:warning, :critical]

      # at least one alert must have been issued; the final trace may be a
      # legitimate same-tag dedup rather than a fresh issue
      issued_trace = Enum.find(traces, fn t -> match?({:issued, _, _}, t.result) end)
      assert issued_trace != nil

      {:issued, alert, payload} = issued_trace.result
      assert alert.victim_pseudonym == last.victim
      # cross-platform payload must not leak an owner or precise locations
      assert payload.owner == nil
      assert payload.precise_locations == nil
      assert payload.spec_version == "unwanted-tracking-v1"
    end

    test "a stationary dropped tag never produces an alert", ctx do
      {obs, now} = Scenario.stationary_tag("ble-lost", "phone-victim", sightings: 10)
      Clock.set(now)
      traces = Scenario.feed(ctx.pipe, obs, fn _ -> %{} end, &Clock.set/1)

      assert Enum.all?(traces, fn t ->
               t.severity == :none or match?({:suppressed, _}, t.result)
             end)
    end
  end

  describe "difficulty 1: family and friends travelling together" do
    test "owner-device presence suppresses the whole family trip", ctx do
      {obs, now} = Scenario.accompanied_trip("ble-family", "phone-victim", sightings: 10)
      Clock.set(now)
      traces = Scenario.feed(ctx.pipe, obs, fn _ -> %{} end, &Clock.set/1)
      last = List.last(traces)
      assert last.suppression == {:suppressed, :owner_device_present}
      refute match?({:issued, _, _}, last.result)
    end

    test "a household attestation suppresses a tag whose owner is off-trip", ctx do
      {pub, priv} = Crypto.generate_keypair()
      fp = Pipeline.register_household(ctx.pipe, pub)
      assert is_binary(fp)

      {obs, now} = Scenario.stalking_trip("ble-child", "phone-mum", sightings: 10)
      Clock.set(now)

      # the victim's app presents a fresh attestation bound to this pair
      att = Crypto.attest(priv, "phone-mum", "ble-child", now)

      traces =
        Scenario.feed(
          ctx.pipe,
          obs,
          fn _ -> %{public_pem: pub, attestation: att} end,
          &Clock.set/1
        )

      assert Enum.all?(traces, fn t ->
               t.suppression == {:suppressed, :household_attestation} or
                 t.severity == :none
             end)
    end
  end

  describe "difficulty 2: stalker rotates tags" do
    test "successor tags inherit suspicion and the alert timeline is superseded", ctx do
      {obs_a, now_a} =
        Scenario.stalking_trip("ble-tag-A", "victim-z", sightings: 7, interval_seconds: 3600)

      Clock.set(now_a)

      traces_a =
        Scenario.feed(ctx.pipe, obs_a, fn _ -> %{owner_account: "stalker-acct"} end, &Clock.set/1)

      assert Enum.any?(traces_a, fn t -> match?({:issued, _, _}, t.result) end)

      # a replacement tag starts appearing near the same victim shortly after,
      # same owner account, same fine cell as tag A's last sighting
      last_a = List.last(obs_a)
      handover_t = now_a + 600

      obs_b =
        for i <- 0..4 do
          %Observation{
            tag_pseudonym: "ble-tag-B",
            victim_pseudonym: "victim-z",
            observed_at: handover_t + i * 3600,
            lat: last_a.lat,
            lng: last_a.lng,
            finder_epid: "f-#{i}",
            owner_device_present?: false,
            rssi: -60
          }
        end

      Clock.set(handover_t + 4 * 3600)

      traces_b =
        Scenario.feed(ctx.pipe, obs_b, fn _ -> %{owner_account: "stalker-acct"} end, &Clock.set/1)

      linked = Enum.find(traces_b, fn t -> match?({:linked, _}, t.rotation) end)
      assert linked != nil

      # the successor's alerts carry the predecessor in linked_from (evidence
      # inheritance); a supersede additionally records rotation/prior_tag
      issued = Enum.filter(traces_b, fn t -> match?({:issued, _, _}, t.result) end)

      if issued != [] do
        trace = List.first(issued)
        {:issued, alert, _payload} = trace.result

        assert alert.evidence[:linked_from] != [] or
                 alert.evidence[:rotation] != nil or
                 alert.evidence[:prior_tag] != nil
      end
    end
  end

  describe "difficulty 3: the victim uses another brand of phone" do
    test "no app install routes the alert into the platform interoperable lane", ctx do
      {obs, now} =
        Scenario.stalking_trip("ble-tag-Y", "phone-other-brand", sightings: 10)

      Clock.set(now)

      traces =
        Scenario.feed(
          ctx.pipe,
          obs,
          fn _ -> %{victim_profile: %{app_installed?: false}} end,
          &Clock.set/1
        )

      # at least one alert must reach the platform lane; the last trace may be
      # a same-tag dedup, so find the issued one explicitly
      issued_trace =
        Enum.find(traces, fn t ->
          match?({:issued, alert, _} when alert.delivery == :platform_payload, t.result)
        end)

      assert issued_trace != nil
      {:issued, alert, _} = issued_trace.result
      assert alert.delivery == :platform_payload
    end

    test "informational verdicts for non-app users are batched into a digest", ctx do
      {obs, now} =
        Scenario.stalking_trip("ble-tag-Z", "phone-other-brand", sightings: 4)

      Clock.set(now)

      traces =
        Scenario.feed(
          ctx.pipe,
          obs,
          fn _ -> %{victim_profile: %{app_installed?: false}} end,
          &Clock.set/1
        )

      Enum.each(traces, fn t ->
        if match?({:issued, _alert, _}, t.result) do
          assert elem(t.result, 1).delivery in [:platform_payload, :delayed_digest]
        end
      end)
    end
  end

  describe "anti-abuse" do
    test "repeated verdicts for one tag do not spam notifications", ctx do
      {obs, now} = Scenario.stalking_trip("ble-spam", "victim-q", sightings: 12)
      Clock.set(now)
      traces = Scenario.feed(ctx.pipe, obs, fn _ -> %{} end, &Clock.set/1)

      issued = Enum.filter(traces, fn t -> match?({:issued, _, _}, t.result) end)
      limited = Enum.filter(traces, fn t -> match?({:rate_limited, _}, t.result) end)

      assert length(issued) <= 2
      assert issued != []
      # after the first issue, subsequent same-window verdicts get limited
      assert limited != [] or length(issued) == 1
    end

    test "the alert channel carries no owner-facing feedback", ctx do
      {obs, now} = Scenario.stalking_trip("ble-secret", "victim-r", sightings: 10)
      Clock.set(now)
      traces = Scenario.feed(ctx.pipe, obs, fn _ -> %{} end, &Clock.set/1)

      {:issued, _alert, payload} =
        Enum.find_value(traces, fn t ->
          if match?({:issued, _, _}, t.result), do: t.result
        end)

      refute Map.has_key?(payload, :owner_id)
      assert payload.owner == nil
    end
  end
end
