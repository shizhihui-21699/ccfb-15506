defmodule SafeFinder.GeoCell do
  @moduledoc """
  Multi-resolution discrete grid cells used for every spatial comparison.

  The detection engine never compares raw coordinates; it compares cell ids.
  Two resolutions are used:

  * level 7 (~150 m edge near the equator) - "same place" for a sighting.
  * level 5 (~1.2 km edge) - "same neighbourhood" for tolerant co-movement.

  This is an intentionally dependency-free equirectangular discretization
  (uniform lat/lng bins). It is accurate enough for proximity logic and keeps
  the whole project buildable offline. The behaviour is defined behind these
  functions so an H3/S2 backend can be swapped in without touching callers.
  """

  @level7_meters 150.0
  @level5_meters 1200.0
  @earth_radius_m 6_371_000.0

  @doc "Edge length in metres of a cell at a given level (levels 5 and 7)."
  def edge_meters(7), do: @level7_meters
  def edge_meters(5), do: @level5_meters

  @doc """
  Returns the opaque cell id for a coordinate at `level`.

  Longitude bins are scaled by `cos(lat)` so that a cell keeps roughly constant
  physical width away from the equator. Output is a short keyed hash rather
  than the raw bin indices, so cell ids cannot be trivially decoded back to a
  coordinate by an operator reading the store.
  """
  @spec cell_id(float(), float(), pos_integer(), binary()) :: binary()
  def cell_id(lat, lng, level, grid_key) do
    edge = edge_meters(level)
    lat_delta = edge / @earth_radius_m
    lng_delta = lat_delta / max(:math.cos(deg_to_rad(lat)), 0.15)

    lat_bin = floor(lat / rad_to_deg(lat_delta))
    lng_bin = floor(lng / rad_to_deg(lng_delta))

    SafeFinder.Hashing.keyed_hash("cell:#{level}", "#{lat_bin}:#{lng_bin}", grid_key)
  end

  @doc "Cell ids at every supported level for one coordinate."
  @spec cells(float(), float(), binary()) :: %{pos_integer() => binary()}
  def cells(lat, lng, grid_key) do
    %{5 => cell_id(lat, lng, 5, grid_key), 7 => cell_id(lat, lng, 7, grid_key)}
  end

  @doc """
  Distance in metres between two coordinates (haversine). Used only for
  corroboration and tests, never as a stored value.
  """
  @spec distance_m({float(), float()}, {float(), float()}) :: float()
  def distance_m({lat1, lng1}, {lat2, lng2}) do
    phi1 = deg_to_rad(lat1)
    phi2 = deg_to_rad(lat2)
    d_phi = deg_to_rad(lat2 - lat1)
    d_lambda = deg_to_rad(lng2 - lng1)

    a =
      :math.sin(d_phi / 2) ** 2 +
        :math.cos(phi1) * :math.cos(phi2) * :math.sin(d_lambda / 2) ** 2

    2 * @earth_radius_m * :math.asin(min(1.0, :math.sqrt(a)))
  end

  defp deg_to_rad(d), do: d * :math.pi() / 180.0
  defp rad_to_deg(r), do: r * 180.0 / :math.pi()
end
