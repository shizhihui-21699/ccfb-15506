defmodule SafeFinder.CrossPlatform do
  @moduledoc """
  Reaching victims whose phones are not our brand, without weakening
  anonymity.

  Detection that only works inside our own app would leave the most likely
  target of a covert tag - someone with no relationship to the manufacturer -
  unprotected. The design therefore follows the 2023 Apple/Google joint
  specification for unwanted tracking alerts, which defines an interoperable
  BLE behaviour any compliant OS can detect locally:

  1. **On-device detection is the primary path for non-customers.** Our tags
     broadcast the standardized frame; iOS ("Item Safety Alerts") and Android
     ("Unknown tracker alerts") raise the system-level notice entirely on the
     victim's phone. The backend is not involved and learns nothing.
  2. **A standardized instruction payload** lets the victim tap the alert,
     read instructions on a neutral web page, and play a sound / see pairing
     metadata. This module builds that payload.
  3. **The backend is the fallback for the long-duration, multi-session
     cases** on-device detectors miss (tag off during travel, observer gaps):
     when our network infers a victim-scoped suspicion but no app install
     exists, the result is published into the interoperable alert lane the
     platform polls, addressed to a rotating victim-side key, never to an
     identity.
  """

  alias SafeFinder.Types.Alert

  @version "unwanted-tracking-v1"

  @doc """
  Build the platform-interoperable payload for an alert.

  The payload contains no owner identity and no precise location. It carries
  only what a victim needs to understand and locate the tag, plus a rotating
  reply key the platform uses to acknowledge receipt without revealing who the
  victim is.
  """
  @spec payload(Alert.t(), map()) :: map()
  def payload(%Alert{} = alert, opts \\ %{}) do
    %{
      spec_version: @version,
      alert_lane: :unwanted_tracking,
      victim_reply_key: Map.get_lazy(opts, :victim_reply_key, fn -> rotating_key(alert) end),
      severity: alert.severity,
      tag: %{
        # the current rotating pseudonym only; prior pseudonyms stay backend-side
        pseudonym: Base.encode16(alert.tag_pseudonym, case: :lower),
        sound_available: Map.get(opts, :sound_available, true),
        instruction_url: instruction_url(alert),
        pairing_hint: Map.get(opts, :pairing_hint, nil)
      },
      timeline: %{
        first_seen_hint: relative_hint(alert.evidence[:factors][:duration_seconds]),
        confidence_band: confidence_band(alert.evidence[:confidence] || 0.0)
      },
      # explicitly absent fields, documenting the privacy boundary
      owner: nil,
      precise_locations: nil
    }
  end

  @doc """
  Choose the delivery lane for a victim.

  * `:app_push`            - our app installed, rich in-app guidance.
  * `:platform_payload`    - no app; standardized OS-level alert lane.
  * `:delayed_digest`      - low-confidence informational notices are batched
                             so a single ambiguous day never nags the user.
  """
  @spec delivery_for(map(), Alert.severity()) :: Alert.delivery()
  def delivery_for(victim_profile, severity) do
    cond do
      Map.get(victim_profile, :app_installed?) -> :app_push
      severity == :informational -> :delayed_digest
      true -> :platform_payload
    end
  end

  @doc """
  Neutral, non-identifying instruction URL. Hosted on a shared safety domain
  so visiting it reveals nothing about which network or victim is involved.
  """
  @spec instruction_url(Alert.t()) :: binary()
  def instruction_url(%Alert{} = alert) do
    tag_hint =
      :crypto.hash(:sha256, [alert.tag_pseudonym, "instruction"])
      |> Base.url_encode64(padding: false)
      |> binary_part(0, 16)

    "https://safety.example/unwanted-tracker?h=#{tag_hint}"
  end

  defp rotating_key(alert) do
    :crypto.hash(:sha256, ["reply", alert.victim_pseudonym, alert.alert_id])
    |> Base.encode16(case: :lower)
  end

  defp confidence_band(c) when c >= 0.85, do: :high
  defp confidence_band(c) when c >= 0.55, do: :medium
  defp confidence_band(_), do: :low

  defp relative_hint(seconds) when is_integer(seconds) and seconds >= 3600 do
    "#{div(seconds, 3600)}h"
  end

  defp relative_hint(seconds) when is_integer(seconds), do: "#{div(seconds, 60)}m"
  defp relative_hint(_), do: "unknown"
end
