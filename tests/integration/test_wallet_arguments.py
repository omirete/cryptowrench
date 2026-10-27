"""Constructor arguments reject invalid Python types."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_constructor_rejects_invalid_entropy_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(entropy="00" * 16)


def test_constructor_rejects_invalid_mnemonic_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(mnemonic=123)


def test_constructor_rejects_invalid_seed_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(seed="seed")


def test_constructor_rejects_invalid_private_key_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(private_key="key")


def test_constructor_rejects_invalid_wif_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(wif=b"wif")


def test_constructor_rejects_invalid_chain_code_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(chain_code="code")


def test_constructor_rejects_invalid_strength_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(strength=True)


def test_constructor_rejects_invalid_language_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(language=123)


def test_constructor_rejects_invalid_passphrase_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(passphrase=b"password")


def test_constructor_rejects_invalid_main_net_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(main_net=1)


def test_constructor_rejects_invalid_derivation_path_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(derivation_path="m")


def test_constructor_rejects_invalid_fingerprint_parent_key_type():
    """This constructor argument has the wrong Python type."""
    with pytest.raises(TypeError):
        Wallet(fingerprint_parent_key="0000")
