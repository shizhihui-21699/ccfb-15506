defmodule SafeFinder.Types do
  @moduledoc """
  Core domain types for the anti-stalking detection backend.

  The network is anonymous by construction:

  * A tag broadcasts a *rotating* BLE pseudonym (`tag_pseudonym`) that changes
    every ~15 minutes. The backend never sees a stable hardware id.
  * A finder phone that relays a sighting is identified only by an unlinkable
    per-report ephemeral id (`finder_epid`). The backend cannot build a finder
    movement history.
  * A person carrying a phone running our app (or a platform-level detector)
    appears under a *victim-side pseudonym* (`victim_pseudonym`) that is also
    rotated and namespaced to the detection subsystem.

  None of these identifiers map to a real-world identity inside the backend.
  """

  defmodule Observation do
    @moduledoc """
    One relayed BLE sighting.

    * `observed_at` - unix seconds, always UTC.
    * `lat` / `lng` - coarse finder-reported coordinates, already snapped
      server-side to a privacy grid cell (see `SafeFinder.GeoCell`).
    * `owner_device_present?` - the finder stack attesting that the tag's
      registered owner device is also advertising nearby. When true the
      sighting is treated as accompanied and never contributes to a suspicion.
    * `rssi` - signal strength, used only to corroborate physical proximity.
    """
    @enforce_keys [:tag_pseudonym, :victim_pseudonym, :observed_at, :lat, :lng]
    defstruct [
      :tag_pseudonym,
      :victim_pseudonym,
      :observed_at,
      :lat,
      :lng,
      finder_epid: nil,
      owner_device_present?: false,
      rssi: nil
    ]

    @type t :: %__MODULE__{
            tag_pseudonym: binary(),
            victim_pseudonym: binary(),
            observed_at: integer(),
            lat: float(),
            lng: float(),
            finder_epid: binary() | nil,
            owner_device_present?: boolean(),
            rssi: integer() | nil
          }
  end

  defmodule Cluster do
    @moduledoc """
    The accumulated co-movement state for one `(victim, tag)` pair.

    A cluster is the unit the detection engine reasons about. It deliberately
    stores only privacy-grid cells and timestamps - never raw coordinates -
    and is pruned aggressively by the retention layer.
    """
    @enforce_keys [:victim_pseudonym, :tag_pseudonym]
    defstruct [
      :victim_pseudonym,
      :tag_pseudonym,
      :owner_account,
      sightings: [],
      distinct_cells: MapSet.new(),
      first_seen: nil,
      last_seen: nil,
      accompanied_count: 0,
      unaccompanied_count: 0,
      linked_from: [],
      confidence: 0.0
    ]

    @type sighting :: %{
            cell: binary(),
            at: integer(),
            owner_device_present?: boolean(),
            rssi: integer() | nil
          }

    @type t :: %__MODULE__{
            victim_pseudonym: binary(),
            tag_pseudonym: binary(),
            sightings: [sighting()],
            distinct_cells: MapSet.t(binary()),
            first_seen: integer() | nil,
            last_seen: integer() | nil,
            accompanied_count: non_neg_integer(),
            unaccompanied_count: non_neg_integer(),
            linked_from: [binary()],
            confidence: float()
          }
  end

  defmodule Alert do
    @moduledoc """
    A suspicion notice addressed to a victim-side pseudonym.

    Alerts are one-directional: they carry no information back to the tag
    owner, so a stalker cannot use the alert channel to learn where the
    victim is or whether detection fired.
    """
    @enforce_keys [:alert_id, :victim_pseudonym, :severity, :issued_at, :reason]
    defstruct [
      :alert_id,
      :victim_pseudonym,
      :tag_pseudonym,
      :severity,
      :issued_at,
      :reason,
      :evidence,
      :delivery,
      :superseded_by
    ]

    @type severity :: :informational | :warning | :critical
    @type delivery :: :app_push | :platform_payload | :delayed_digest

    @type t :: %__MODULE__{
            alert_id: binary(),
            victim_pseudonym: binary(),
            tag_pseudonym: binary(),
            severity: severity(),
            issued_at: integer(),
            reason: atom(),
            evidence: map(),
            delivery: delivery(),
            superseded_by: binary() | nil
          }
  end
end
