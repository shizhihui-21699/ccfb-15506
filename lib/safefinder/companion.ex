defmodule SafeFinder.Companion do
  @moduledoc """
  Decides whether a co-moving tag is *expected* (family / friends travelling
  together) and must therefore be suppressed without weakening detection of
  genuine stalking.

  Two independent, privacy-preserving suppression paths exist:

  1. **Owner-device presence.** If the BLE stack on a relaying phone attests
     that the tag's registered owner device is physically advertising right
     beside the tag, the tag is accompanied by its owner. A stalker cannot
     forge this: it requires the owner's actual device to be present. This
     handles "partner's tag in the shared car" with zero configuration.

  2. **Household safe-list attestation.** For tags whose owner is not on this
     trip but who belongs to the victim's household (a child's bag tag while
     mum drives), the victim's phone holds a signed, time-bounded attestation
     from the household key. The backend only verifies a signature; it stores
     no relationship graph. See `SafeFinder.Crypto`.

  Suppression is deliberately narrow: it applies to the exact
  `(victim, tag)` pair named in the proof and only while the proof is fresh.
  It can never be used by a tag owner to globally silence alerts about their
  own tag, which would be a stalker's first wish.
  """

  alias SafeFinder.Crypto

  @typedoc "A verified household public key stored under an opaque fingerprint."
  @type safe_list :: %{binary() => Crypto.public_pem()}

  @doc """
  True when the owner's own device was present for a strong enough fraction of
  recent sightings **and** there is enough history to make the claim
  meaningful. A single accompanied sighting does not suppress: a stalker who
  briefly passes the owner must not reset the signal. Requires at least 4
  samples and an 80% accompanied ratio by default.
  """
  @spec owner_accompanied?([map()], float(), pos_integer()) :: boolean()
  def owner_accompanied?(recent_sightings, threshold \\ 0.8, min_samples \\ 4)
  def owner_accompanied?([], _, _), do: false

  def owner_accompanied?(recent_sightings, threshold, min_samples) do
    length(recent_sightings) >= min_samples and
      Enum.count(recent_sightings, & &1.owner_device_present?) /
        length(recent_sightings) >=
        threshold
  end

  @doc """
  Verify a household attestation for a specific victim/tag pair.

  Returns `{:ok, household_fingerprint}` on success or an error reason. The
  caller uses the fingerprint only to record *which* proof suppressed the
  alert, never to expand suppression to other tags.
  """
  @spec household_attested?(
          safe_list(),
          Crypto.public_pem() | nil,
          map(),
          binary(),
          binary(),
          integer()
        ) ::
          {:ok, binary()} | {:error, atom()}
  def household_attested?(_safe_list, nil, _att, _victim, _tag, _now),
    do: {:error, :no_attestation}

  def household_attested?(safe_list, public_pem, att, victim, tag, now) do
    with :ok <- Crypto.verify_attestation(public_pem, att, victim, tag, now) do
      fp = Crypto.fingerprint(public_pem)

      if Map.has_key?(safe_list, fp) do
        {:ok, fp}
      else
        {:error, :unregistered_household_key}
      end
    end
  end

  @doc """
  Top-level suppression decision for a candidate alert.

  `evidence` is a map carrying optional `:attestation` and `:public_pem`
  supplied by the victim's app, plus the cluster's recent sightings. Any
  suppression is returned with its basis so it is auditable; denials fall
  through to alerting.
  """
  @spec suppression_basis(safe_list(), map(), [map()], integer()) ::
          {:suppressed, atom()} | :not_suppressed
  def suppression_basis(safe_list, evidence, recent_sightings, now) do
    cond do
      owner_accompanied?(recent_sightings) ->
        {:suppressed, :owner_device_present}

      match?(
        {:ok, _},
        household_attested?(
          safe_list,
          evidence[:public_pem],
          evidence[:attestation],
          evidence[:victim_pseudonym],
          evidence[:tag_pseudonym],
          now
        )
      ) ->
        {:suppressed, :household_attestation}

      true ->
        :not_suppressed
    end
  end
end
