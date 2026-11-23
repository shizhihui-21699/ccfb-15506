defmodule SafeFinder.Test.Scenario do
  @moduledoc """
  Builds deterministic observation streams for detection tests.

  A "trip" is a sequence of unaccompanied sightings spread across distinct
  grid cells over time - exactly the shape a covert tag hidden on a person
  produces. Helpers also produce the benign shapes (a stationary lost tag, an
  owner-accompanied family tag, a one-off shared commute) so false-positive
  behaviour can be asserted directly.
  """

  alias SafeFinder.Types.Observation

  @base_t 1_700_000_000

  # Distinct coordinates far enough apart to land in different level-7 cells.
  @stops [
    {31.2304, 121.4737},
    {31.2380, 121.4800},
    {31.2460, 121.4870},
    {31.2540, 121.4940},
    {31.2620, 121.5010}
  ]

  @doc "Fixed unix base time; tests add explicit offsets for full control."
  def base_t, do: @base_t

  @doc """
  A sustained unaccompanied trip: `n` sightings, one per stop (cycling), one
  hour apart, all with the owner absent. Returns `{observations, final_now}`.
  """
  def stalking_trip(tag, victim, opts \\ []) do
    n = Keyword.get(opts, :sightings, 8)
    interval = Keyword.get(opts, :interval_seconds, 60 * 60)
    start_t = Keyword.get(opts, :start_t, @base_t)
    stops = Keyword.get(opts, :stops, @stops)

    observations =
      for i <- 0..(n - 1) do
        {lat, lng} = Enum.at(stops, rem(i, length(stops)))

        %Observation{
          tag_pseudonym: tag,
          victim_pseudonym: victim,
          observed_at: start_t + i * interval,
          lat: lat,
          lng: lng,
          finder_epid: "finder-#{i}-#{:erlang.phash2({tag, i})}",
          owner_device_present?: false,
          rssi: -60
        }
      end

    {observations, start_t + (n - 1) * interval}
  end

  @doc "A tag that never moves: repeated sightings on one coordinate (dropped tag)."
  def stationary_tag(tag, victim, opts \\ []) do
    n = Keyword.get(opts, :sightings, 8)
    start_t = Keyword.get(opts, :start_t, @base_t)
    {lat, lng} = Keyword.get(opts, :at, hd(@stops))

    observations =
      for i <- 0..(n - 1) do
        %Observation{
          tag_pseudonym: tag,
          victim_pseudonym: victim,
          observed_at: start_t + i * 60 * 60,
          lat: lat,
          lng: lng,
          finder_epid: "finder-static-#{i}",
          owner_device_present?: false,
          rssi: -70
        }
      end

    {observations, start_t + (n - 1) * 60 * 60}
  end

  @doc """
  A family trip: same shape as a stalking trip but every sighting attests the
  owner device is physically present. Optionally inject household attestation
  metadata into the returned keyword list for pipeline-level tests.
  """
  def accompanied_trip(tag, victim, opts \\ []) do
    {observations, now} = stalking_trip(tag, victim, opts)

    observations =
      Enum.map(observations, fn obs ->
        %{obs | owner_device_present?: true}
      end)

    {observations, now}
  end

  @doc "A single brief encounter - stranger sharing one train ride."
  def brief_encounter(tag, victim, opts \\ []) do
    start_t = Keyword.get(opts, :start_t, @base_t)
    {lat, lng} = Keyword.get(opts, :at, hd(@stops))

    obs = %Observation{
      tag_pseudonym: tag,
      victim_pseudonym: victim,
      observed_at: start_t,
      lat: lat,
      lng: lng,
      finder_epid: "finder-brief",
      owner_device_present?: false,
      rssi: -65
    }

    {[obs], start_t}
  end

  @doc """
  Feed a list of observations through a pipeline with a controllable clock.

  The pipeline evaluates lazily at each ingest against its injected `now`
  function, so the clock must advance with the observations; `clock_set/1`
  (typically the test's `Clock.set/1`) is invoked before every ingest.
  """
  def feed(pipeline, observations, meta_fun \\ fn _ -> %{} end, clock_set \\ fn _ -> :ok end) do
    Enum.map(observations, fn obs ->
      clock_set.(obs.observed_at)
      SafeFinder.Pipeline.ingest(pipeline, obs, meta_fun.(obs))
    end)
  end
end
