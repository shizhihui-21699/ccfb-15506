defmodule SafeFinder.Crypto do
  @moduledoc """
  Asymmetric signatures for household / companion safe-list attestations.

  A family wants their own tags to travel together without generating alerts.
  Rather than ask the backend to remember who lives with whom (a deanonymizing
  social graph), each household is represented by a keypair generated on a
  member's phone:

  * The private key stays on phones; the backend only ever sees a public key.
  * A phone emits a short-lived `attestation` proving "this tag belongs to a
    household that also includes this victim device", signed by the household
    key and time-bounded.
  * The backend verifies the signature and the expiry window, then suppresses
    the suspicion. It learns nothing about household membership beyond the
    single proof in front of it.

  RSA-2048 with PKCS1-SHA256 is used because it is available through the
  Erlang `:public_key` application on every supported OTP release with no
  external dependency. The record shapes here are isolated so the algorithm
  can be upgraded independently of the detection logic.
  """

  @typedoc "PEM-encoded RSA private key (held only on client devices)."
  @type private_pem :: binary()
  @typedoc "PEM-encoded RSA public key (the only half the backend stores)."
  @type public_pem :: binary()

  @doc "Generate a household keypair, returning `{public_pem, private_pem}`."
  @spec generate_keypair() :: {public_pem(), private_pem()}
  def generate_keypair do
    priv = :public_key.generate_key({:rsa, 2048, 65537})
    priv_pem = encode_pem(:RSAPrivateKey, priv)
    pub = {:RSAPublicKey, elem(priv, 2), elem(priv, 3)}
    pub_pem = encode_pem(:RSAPublicKey, pub)
    {pub_pem, priv_pem}
  end

  @doc """
  Produce a compact, time-bounded attestation binary and its signature.

  The payload binds together the household public key, the victim device
  pseudonym and the tag pseudonym, plus an expiry. Reusing an attestation for
  a different victim/tag fails verification because those fields are signed.
  """
  @spec attest(private_pem(), binary(), binary(), integer(), integer()) ::
          %{payload: binary(), signature: binary(), expires_at: integer()}
  def attest(private_pem, victim_pseudonym, tag_pseudonym, now_unix, ttl_seconds \\ 86_400) do
    priv = decode_pem!(private_pem)
    expires_at = now_unix + ttl_seconds
    # Fingerprint is always derived from the public half, so a signature and
    # its verification compute the identical value despite holding different
    # halves of the keypair.
    pub = public_from_private(priv)

    payload =
      :erlang.term_to_binary(
        {:safe_list_v1, fingerprint(pub), victim_pseudonym, tag_pseudonym, expires_at}
      )

    signature = :public_key.sign(payload, :sha256, priv)
    %{payload: payload, signature: signature, expires_at: expires_at}
  end

  @doc """
  Verify an attestation against a stored household public key.

  Returns `:ok` or `{:error, reason}`. Checks in order: signature validity,
  structural integrity of the signed payload, binding to the exact
  victim/tag pair, and expiry.
  """
  @spec verify_attestation(public_pem(), map(), binary(), binary(), integer()) ::
          :ok | {:error, atom()}
  def verify_attestation(public_pem, att, victim_pseudonym, tag_pseudonym, now_unix) do
    with {:ok, pub} <- safe_decode_public(public_pem),
         true <-
           :public_key.verify(att.payload, :sha256, att.signature, pub) ||
             {:error, :bad_signature},
         {:safe_list_v1, key_fp, victim, tag, expires_at} <-
           safe_binary_to_term(att.payload),
         true <- key_fp == fingerprint(pub) || {:error, :key_mismatch},
         true <- victim == victim_pseudonym || {:error, :victim_mismatch},
         true <- tag == tag_pseudonym || {:error, :tag_mismatch},
         true <- now_unix < expires_at || {:error, :expired} do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :malformed_attestation}
    end
  end

  @doc "Stable hex fingerprint of a public key, used as the household handle."
  @spec fingerprint(public_pem() | tuple()) :: binary()
  def fingerprint(public_pem) when is_binary(public_pem) do
    public_pem |> safe_decode_public!() |> fingerprint()
  end

  def fingerprint(key_record) do
    :crypto.hash(:sha256, :erlang.term_to_binary(strip(key_record)))
    |> Base.encode16(case: :lower)
  end

  # --- internals -----------------------------------------------------------

  defp encode_pem(type, record) do
    :public_key.pem_entry_encode(type, record)
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  defp decode_pem!(pem) do
    pem |> :public_key.pem_decode() |> hd() |> :public_key.pem_entry_decode()
  end

  defp safe_decode_public(pem) do
    {:ok, safe_decode_public!(pem)}
  rescue
    _ -> {:error, :malformed_public_key}
  end

  defp safe_decode_public!(pem) do
    entry = pem |> :public_key.pem_decode() |> hd()

    case :public_key.pem_entry_decode(entry) do
      {:RSAPublicKey, _, _} = pub -> pub
      {:RSAPrivateKey, _, n, e, _, _, _, _, _} -> {:RSAPublicKey, n, e}
    end
  end

  # :erlang.binary_to_term is unsafe on attacker-controlled input; the payload
  # signature is checked first, but we still pin the allowed term shape.
  defp safe_binary_to_term(bin) do
    term = :erlang.binary_to_term(bin, [:safe])

    case term do
      {:safe_list_v1, fp, victim, tag, exp}
      when is_binary(fp) and is_binary(victim) and is_binary(tag) and is_integer(exp) ->
        term

      _ ->
        throw({:error, :malformed_payload})
    end
  catch
    _, _ -> {:error, :malformed_payload}
  end

  defp strip({:RSAPublicKey, n, e}), do: {:rsa_pub, n, e}
  defp strip(other), do: other

  defp public_from_private({:RSAPrivateKey, _version, n, e, _d, _p, _q, _e1, _e2, _ct, _}),
    do: {:RSAPublicKey, n, e}
end
