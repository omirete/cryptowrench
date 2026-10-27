"""Explicit constructor examples using the private key source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_private_key_creation_rejects_strength(root_wallet, strength):
    """Private key creation rejects the strength option."""
    with pytest.raises(ValueError) as error:
        Wallet(private_key=root_wallet.private_key, strength=strength)
    assert "strength" in str(error.value)
    assert "private_key" in str(error.value)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_private_key_creation_rejects_language(root_wallet, language):
    """Private key creation rejects the language option."""
    with pytest.raises(ValueError) as error:
        Wallet(private_key=root_wallet.private_key, language=language)
    assert "language" in str(error.value)
    assert "private_key" in str(error.value)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_private_key_creation_rejects_passphrase(root_wallet, passphrase):
    """Private key creation rejects the passphrase option."""
    with pytest.raises(ValueError) as error:
        Wallet(private_key=root_wallet.private_key, passphrase=passphrase)
    assert "passphrase" in str(error.value)
    assert "private_key" in str(error.value)


@pytest.mark.parametrize("main_net", [True, False])
def test_private_key_creation_accepts_main_net(root_wallet, main_net):
    """Private key creation accepts the main_net option."""
    Wallet(private_key=root_wallet.private_key, main_net=main_net)


def test_private_key_creation_accepts_zero_bytes_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    Wallet(private_key=root_wallet.private_key, chain_code=chain_code)


def test_private_key_creation_accepts_root_wallet_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    Wallet(private_key=root_wallet.private_key, chain_code=chain_code)


def test_private_key_creation_none_options_match_omitted_options(
    root_wallet, deterministic_randomness
):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet(private_key=root_wallet.private_key)
    none_options_wallet = Wallet(
        entropy=None,
        mnemonic=None,
        seed=None,
        private_key=root_wallet.private_key,
        wif=None,
        chain_code=None,
        strength=None,
        derivation_path=None,
        fingerprint_parent_key=None,
        language=None,
        passphrase=None,
        main_net=None,
    )
    assert none_options_wallet.__dict__ == omitted_options_wallet.__dict__


def test_private_key_creation_network_changes_address(
    root_wallet, deterministic_randomness
):
    """Network selection changes the Bitcoin address while preserving the private key."""
    mainnet_wallet = Wallet(private_key=root_wallet.private_key, main_net=True)
    testnet_wallet = Wallet(private_key=root_wallet.private_key, main_net=False)
    assert mainnet_wallet.private_key == testnet_wallet.private_key
    assert mainnet_wallet.address.bitcoin.P2PKH != testnet_wallet.address.bitcoin.P2PKH


def test_extended_private_key_preserves_chain_code(root_wallet):
    """An imported extended key keeps its chain code; the path m selects its root."""
    imported_wallet = Wallet(
        private_key=root_wallet.private_key, chain_code=root_wallet.chain_code
    )
    assert imported_wallet.chain_code == root_wallet.chain_code
    master_wallet = imported_wallet.hd_wallet("m")
    assert master_wallet.private_key == root_wallet.private_key
