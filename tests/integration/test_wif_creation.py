"""Explicit constructor examples using the wif source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_wif_creation_rejects_strength(root_wallet, strength):
    """Wif creation rejects the strength option."""
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, strength=strength)
    assert "strength" in str(error.value)
    assert "wif" in str(error.value)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_wif_creation_rejects_language(root_wallet, language):
    """Wif creation rejects the language option."""
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, language=language)
    assert "language" in str(error.value)
    assert "wif" in str(error.value)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_wif_creation_rejects_passphrase(root_wallet, passphrase):
    """Wif creation rejects the passphrase option."""
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, passphrase=passphrase)
    assert "passphrase" in str(error.value)
    assert "wif" in str(error.value)


@pytest.mark.parametrize("main_net", [True, False])
def test_wif_creation_rejects_main_net(root_wallet, main_net):
    """Wif creation rejects the main_net option."""
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, main_net=main_net)
    assert "main_net" in str(error.value)
    assert "wif" in str(error.value)


def test_wif_creation_rejects_zero_bytes_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "wif" in str(error.value)


def test_wif_creation_rejects_root_wallet_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    with pytest.raises(ValueError) as error:
        Wallet(wif=root_wallet.wif, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "wif" in str(error.value)


def test_wif_creation_none_options_match_omitted_options(
    root_wallet, deterministic_randomness
):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet(wif=root_wallet.wif)
    none_options_wallet = Wallet(
        entropy=None,
        mnemonic=None,
        seed=None,
        private_key=None,
        wif=root_wallet.wif,
        chain_code=None,
        strength=None,
        derivation_path=None,
        fingerprint_parent_key=None,
        language=None,
        passphrase=None,
        main_net=None,
    )
    assert none_options_wallet.__dict__ == omitted_options_wallet.__dict__
