"""Invalid import values must fail without changing an existing wallet."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_seed_text_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_seed(seed="seed")

    assert wallet.__dict__ == original_state


def test_mnemonic_integer_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_mnemonic(mnemonic=123)

    assert wallet.__dict__ == original_state


def test_mnemonic_invalid_words_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_mnemonic(mnemonic="not a mnemonic")

    assert wallet.__dict__ == original_state


def test_mnemonic_invalid_checksum_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_mnemonic(mnemonic="abandon " * 11 + "abandon")

    assert wallet.__dict__ == original_state


def test_entropy_text_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy="00" * 16)

    assert wallet.__dict__ == original_state


def test_entropy_length_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_entropy(entropy=bytes(15))

    assert wallet.__dict__ == original_state


def test_entropy_language_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_entropy(entropy=bytes(16), language="unknown")

    assert wallet.__dict__ == original_state


def test_private_key_text_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_private_key(private_key="key")

    assert wallet.__dict__ == original_state


def test_private_key_length_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_private_key(private_key=bytes(31))

    assert wallet.__dict__ == original_state


def test_private_key_zero_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_private_key(private_key=bytes(32))

    assert wallet.__dict__ == original_state


def test_extended_private_key_length_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_extended_private_key(private_key=bytes(31), chain_code=bytes(32))

    assert wallet.__dict__ == original_state


def test_extended_chain_code_text_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_extended_private_key(
            private_key=root_wallet.private_key, chain_code="code"
        )

    assert wallet.__dict__ == original_state


def test_wif_bytes_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_wif(wif=b"wif")

    assert wallet.__dict__ == original_state


def test_wif_invalid_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(ValueError):
        wallet.from_wif(wif="invalid")

    assert wallet.__dict__ == original_state
