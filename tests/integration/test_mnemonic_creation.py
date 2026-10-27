"""Explicit constructor examples using the mnemonic source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_mnemonic_creation_rejects_strength(root_wallet, strength):
    """Mnemonic creation rejects the strength option."""
    with pytest.raises(ValueError) as error:
        Wallet(mnemonic=root_wallet.words, strength=strength)
    assert "strength" in str(error.value)
    assert "mnemonic" in str(error.value)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_mnemonic_creation_rejects_language(root_wallet, language):
    """Mnemonic creation rejects the language option."""
    with pytest.raises(ValueError) as error:
        Wallet(mnemonic=root_wallet.words, language=language)
    assert "language" in str(error.value)
    assert "mnemonic" in str(error.value)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_mnemonic_creation_accepts_passphrase(root_wallet, passphrase):
    """Mnemonic creation accepts the passphrase option."""
    Wallet(mnemonic=root_wallet.words, passphrase=passphrase)


@pytest.mark.parametrize("main_net", [True, False])
def test_mnemonic_creation_accepts_main_net(root_wallet, main_net):
    """Mnemonic creation accepts the main_net option."""
    Wallet(mnemonic=root_wallet.words, main_net=main_net)


def test_mnemonic_creation_rejects_zero_bytes_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    with pytest.raises(ValueError) as error:
        Wallet(mnemonic=root_wallet.words, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "mnemonic" in str(error.value)


def test_mnemonic_creation_rejects_root_wallet_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    with pytest.raises(ValueError) as error:
        Wallet(mnemonic=root_wallet.words, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "mnemonic" in str(error.value)


def test_mnemonic_creation_none_options_match_omitted_options(
    root_wallet, deterministic_randomness
):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet(mnemonic=root_wallet.words)
    none_options_wallet = Wallet(
        entropy=None,
        mnemonic=root_wallet.words,
        seed=None,
        private_key=None,
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


def test_mnemonic_creation_passphrase_changes_seed(
    root_wallet, deterministic_randomness
):
    """A passphrase changes the derived seed and is retained for recovery."""
    default_wallet = Wallet()
    protected_wallet = Wallet(mnemonic=root_wallet.words, passphrase="secret")
    assert protected_wallet.seed != default_wallet.seed
    assert protected_wallet.passphrase == "secret"


def test_mnemonic_creation_network_changes_address(
    root_wallet, deterministic_randomness
):
    """Network selection changes the Bitcoin address while preserving the private key."""
    mainnet_wallet = Wallet(mnemonic=root_wallet.words, main_net=True)
    testnet_wallet = Wallet(mnemonic=root_wallet.words, main_net=False)
    assert mainnet_wallet.private_key == testnet_wallet.private_key
    assert mainnet_wallet.address.bitcoin.P2PKH != testnet_wallet.address.bitcoin.P2PKH
