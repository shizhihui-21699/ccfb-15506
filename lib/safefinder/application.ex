defmodule SafeFinder.Application do
  @moduledoc """
  OTP application entry point.

  Supervision topology mirrors the production shape at small scale:

  * `SafeFinder.Alerts` - alert state and anti-abuse policy.
  * `SafeFinder.Pipeline` - ingestion and detection orchestration.

  Both are restarted independently: a crash in alert bookkeeping never stops
  ingestion, and vice versa. In production the pipeline is replaced by a
  `PartitionSupervisor` with one pipeline child per victim-hash partition;
  the detection modules it calls are unchanged.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      SafeFinder.Alerts,
      {SafeFinder.Pipeline, name: SafeFinder.Pipeline}
    ]

    opts = [strategy: :one_for_one, name: SafeFinder.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
