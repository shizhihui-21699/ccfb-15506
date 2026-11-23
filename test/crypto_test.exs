defmodule SafeFinder.CryptoTest do
  use ExUnit.Case, async: true

  alias SafeFinder.Crypto

  setup do
    {pub_pem, priv_pem} = Crypto.generate_keypair()
    %{pub_pem: pub_pem, priv_pem: priv_pem}
  end

  test "generated keypair is RSA PEM and the backend only needs the public half",
       %{pub_pem: pub, priv_pem: priv} do
    assert String.starts_with?(pub, "-----BEGIN RSA PUBLIC KEY-----")
    assert String.starts_with?(priv, "-----BEGIN RSA PRIVATE KEY-----")
    assert Crypto.fingerprint(pub) == Crypto.fingerprint(pub)
  end

  test "a fresh attestation verifies for its exact victim and tag", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now)

    assert :ok =
             Crypto.verify_attestation(ctx.pub_pem, att, "victim-1", "tag-1", now + 10)
  end

  test "attestation cannot be replayed for a different victim", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now)

    assert {:error, :victim_mismatch} =
             Crypto.verify_attestation(ctx.pub_pem, att, "victim-2", "tag-1", now)
  end

  test "attestation cannot be replayed for a different tag", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now)

    assert {:error, :tag_mismatch} =
             Crypto.verify_attestation(ctx.pub_pem, att, "victim-1", "tag-2", now)
  end

  test "an expired attestation is rejected", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now, 60)

    assert {:error, :expired} =
             Crypto.verify_attestation(ctx.pub_pem, att, "victim-1", "tag-1", now + 61)
  end

  test "a tampered signature is rejected", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now)
    tampered = %{att | signature: :crypto.hash(:sha256, att.signature)}

    assert {:error, :bad_signature} =
             Crypto.verify_attestation(ctx.pub_pem, tampered, "victim-1", "tag-1", now)
  end

  test "a malformed public key is handled without raising" do
    assert {:error, :malformed_public_key} =
             Crypto.verify_attestation(
               "not a pem",
               %{payload: "x", signature: "y"},
               "v",
               "t",
               0
             )
  end

  test "a malformed payload cannot crash verification", ctx do
    now = 1_000
    att = Crypto.attest(ctx.priv_pem, "victim-1", "tag-1", now)
    evil_payload = :erlang.term_to_binary(:os.cmd(~c"echo pwned"))
    forged_sig = :public_key.sign(evil_payload, :sha256, pem_priv!(ctx.priv_pem))
    att2 = %{att | payload: evil_payload, signature: forged_sig}

    assert {:error, _} =
             Crypto.verify_attestation(ctx.pub_pem, att2, "victim-1", "tag-1", now)
  end

  defp pem_priv!(pem) do
    pem |> :public_key.pem_decode() |> hd() |> :public_key.pem_entry_decode()
  end
end
