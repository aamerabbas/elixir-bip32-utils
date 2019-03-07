# Additional dependencies needed:
# {:bip32, git: "https://github.com/aamerabbas/bip32"},
# {:pbkdf2_elixir, "~> 0.12"},
# {:base58check, "~> 0.1.0"},
# {:area58check, "~> 0.1.1"},


defmodule AddressUtils do
  @coin_types %{
    testnet: 1,

    btc: 0,
    eth: 60
  }

  @btc_mainnet_prefix 0x00
  @btc_testnet_prefix 0x6F

  def master_node_from_seed(seed) when is_binary(seed) do
    seed
    |> Pbkdf2.Base.hash_password("mnemonic", rounds: 2048, length: 512, format: :hex)
    |> String.slice(0, 128)
    |> Bip32.Node.generate_master_node
  end

  def private_key(%Bip32.Node{private_key: private_key} = node, :btc, network, account, index) when network in [:mainnet, :testnet] and is_binary(private_key) and bit_size(private_key) === 512 do
    node
    |> _private_key(:btc, network, account, index)
    |> Kernel.<>(<<1>>) # To indicate compresssion: https://bitcoin.stackexchange.com/questions/3059#answer-3839
    |> Area58check.encode(:wif)
    |> Map.fetch!(:encoded)
  end

  defp _private_key(node, coin_type, network, account, index) do
    coin_type_code =
      case network do
        :mainnet -> @coin_types[coin_type]
        :testnet -> @coin_types[:testnet]
      end

    node
    |> derive_descendant(coin_type_code, account, index)
    |> Map.fetch!(:private_key)
    |> Base.decode16!(case: :mixed)
  end

  def public_key(%Bip32.Node{private_key: private_key} = node, :btc, :mainnet, account, index) when is_binary(private_key) and bit_size(private_key) === 512 do
    _public_key(node, :btc, @btc_mainnet_prefix, account, index)
  end

  def public_key(%Bip32.Node{private_key: private_key} = node, :btc, :testnet, account, index) when is_binary(private_key) and bit_size(private_key) === 512 do
    _public_key(node, :btc, @btc_testnet_prefix, account, index)
  end

  defp _public_key(node, :btc, net_bytes, account, index) do
    address_public_key =
      node
      |> derive_descendant(@coin_types[:btc], account, index)
      |> Map.fetch!(:public_key)
      |> Base.decode16!(case: :mixed)

    pub_ripemd160 = :crypto.hash(:ripemd160, :crypto.hash(:sha256, address_public_key))
    pub_with_netbytes = <<net_bytes::size(8), pub_ripemd160::binary>>
    <<checksum::binary-4, _rest::binary>> = :crypto.hash(:sha256, :crypto.hash(:sha256, pub_with_netbytes))

    Base58Check.encode58(pub_with_netbytes <> checksum)
  end

  defp derive_descendant(node, coin_type_code, account, index) do
    Bip32.Node.derive_descendant_by_path(node, "m/44'/#{coin_type_code}'/#{account}'/0/#{index}")
  end
end
