defmodule SafeFinder.Hashing do
  @moduledoc """
  Keyed hashing primitives for pseudonymization and linkage.

  All hashing is HMAC-SHA256 under a key held in the detection service's own
  secret compartment. The key never appears in observation payloads and is
  rotated by `SafeFinder.Rotation`, at which point old pseudonyms become
  unlinkable to new ones even for someone with full database access.
  """

  @type hmac_key :: binary()

  @doc "Generate a fresh random HMAC key (32 bytes)."
  @spec new_key() :: hmac_key()
  def new_key, do: :crypto.strong_rand_bytes(32)

  @doc "Deterministic keyed hash, returned as 16 raw bytes (128 bits)."
  @spec keyed_hash(binary(), binary(), hmac_key()) :: binary()
  def keyed_hash(namespace, value, key) do
    :crypto.mac(:hmac, :sha256, key, namespace <> <<0>> <> value)
    |> binary_part(0, 16)
  end

  @doc "Hex-encoded convenience form used in logs and ids."
  @spec keyed_hash_hex(binary(), binary(), hmac_key()) :: binary()
  def keyed_hash_hex(namespace, value, key) do
    Base.encode16(keyed_hash(namespace, value, key), case: :lower)
  end

  @doc """
  Hash a rotating BLE pseudonym against the current key to obtain the stable,
  namespaced handle the engine stores. Rotating BLE addresses of the same
  physical tag are only linkable when the tag's device key allows deriving
  their sequence (see `SafeFinder.Rotation`); this function alone does not
  de-rotate arbitrary addresses.
  """
  @spec pseudonym_handle(binary(), hmac_key()) :: binary()
  def pseudonym_handle(ble_pseudonym, key) do
    keyed_hash("pseudonym", ble_pseudonym, key)
  end
end
