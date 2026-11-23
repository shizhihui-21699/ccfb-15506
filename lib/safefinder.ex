defmodule SafeFinder do
  @moduledoc """
  SafeFinder: the anti-stalking detection backend for an anonymous
  lost-and-found tag network.

  The OTP application wires together:

  * `SafeFinder.Pipeline`   - streaming ingestion and orchestration
  * `SafeFinder.CoMovement` - the pure detection policy
  * `SafeFinder.Companion`  - family / owner-device suppression
  * `SafeFinder.Rotation`   - tag-rotation linkage
  * `SafeFinder.Alerts`     - alert lifecycle and anti-abuse controls
  * `SafeFinder.CrossPlatform` - interoperable alerts for other-brand phones
  * `SafeFinder.Retention`  - deletion and key rotation

  See `DESIGN.md` for the full threat model, protocol assumptions and the
  rationale for each privacy boundary.
  """
end
