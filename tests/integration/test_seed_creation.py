"""Explicit constructor examples using the seed source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_seed_creation_rejects_strength(root_wallet, strength):
    """Seed creation rejects the strength option."""
    with pytest.raises(ValueError) as error:
        Wallet(seed=root_wallet.seed, strength=strength)
    assert "strength" in str(error.value)
    assert "seed" in str(error.value)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_seed_creation_rejects_language(root_wallet, language):
    """Seed creation rejects the language option."""
    with pytest.raises(ValueError) as error:
        Wallet(seed=root_wallet.seed, language=language)
    assert "language" in str(error.value)
    assert "seed" in str(error.value)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_seed_creation_rejects_passphrase(root_wallet, passphrase):
    """Seed creation rejects the passphrase option."""
    with pytest.raises(ValueError) as error:
        Wallet(seed=root_wallet.seed, passphrase=passphrase)
    assert "passphrase" in str(error.value)
    assert "seed" in str(error.value)


@pytest.mark.parametrize("main_net", [True, False])
def test_seed_creation_accepts_main_net(root_wallet, main_net):
    """Seed creation accepts the main_net option."""
    Wallet(seed=root_wallet.seed, main_net=main_net)


def test_seed_creation_rejects_zero_bytes_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    with pytest.raises(ValueError) as error:
        Wallet(seed=root_wallet.seed, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "seed" in str(error.value)


def test_seed_creation_rejects_root_wallet_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    with pytest.raises(ValueError) as error:
        Wallet(seed=root_wallet.seed, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "seed" in str(error.value)


def test_seed_creation_none_options_match_omitted_options(
    root_wallet, deterministic_randomness
):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet(seed=root_wallet.seed)
    none_options_wallet = Wallet(
        entropy=None,
        mnemonic=None,
        seed=root_wallet.seed,
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


def test_seed_creation_network_changes_address(root_wallet, deterministic_randomness):
    """Network selection changes the Bitcoin address while preserving the private key."""
    mainnet_wallet = Wallet(seed=root_wallet.seed, main_net=True)
    testnet_wallet = Wallet(seed=root_wallet.seed, main_net=False)
    assert mainnet_wallet.private_key == testnet_wallet.private_key
    assert mainnet_wallet.address.bitcoin.P2PKH != testnet_wallet.address.bitcoin.P2PKH
