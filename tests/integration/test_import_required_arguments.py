"""Missing or None import arguments must fail without changing an existing wallet."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_seed_omitted_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_seed()

    assert wallet.__dict__ == original_state


def test_seed_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_seed(seed=None)

    assert wallet.__dict__ == original_state


def test_mnemonic_omitted_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_mnemonic()

    assert wallet.__dict__ == original_state


def test_mnemonic_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_mnemonic(mnemonic=None)

    assert wallet.__dict__ == original_state


def test_mnemonic_passphrase_none_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_mnemonic(mnemonic=root_wallet.words, passphrase=None)

    assert wallet.__dict__ == original_state


def test_entropy_omitted_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_entropy()

    assert wallet.__dict__ == original_state


def test_entropy_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=None)

    assert wallet.__dict__ == original_state


def test_entropy_passphrase_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=bytes(16), passphrase=None)

    assert wallet.__dict__ == original_state


def test_entropy_language_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=bytes(16), language=None)

    assert wallet.__dict__ == original_state


def test_private_key_omitted_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_private_key()

    assert wallet.__dict__ == original_state


def test_private_key_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_private_key(private_key=None)

    assert wallet.__dict__ == original_state


def test_extended_chain_code_omitted_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_extended_private_key(private_key=root_wallet.private_key)

    assert wallet.__dict__ == original_state


def test_extended_private_key_omitted_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_extended_private_key(chain_code=root_wallet.chain_code)

    assert wallet.__dict__ == original_state


def test_extended_private_key_none_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_extended_private_key(
            private_key=None, chain_code=root_wallet.chain_code
        )

    assert wallet.__dict__ == original_state


def test_extended_chain_code_none_is_rejected_without_changing_wallet(root_wallet):
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_extended_private_key(
            private_key=root_wallet.private_key, chain_code=None
        )

    assert wallet.__dict__ == original_state


def test_wif_omitted_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_wif()

    assert wallet.__dict__ == original_state


def test_wif_none_is_rejected_without_changing_wallet():
    # Save every stored attribute before attempting the invalid import.
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    original_state = wallet.__dict__.copy()

    # The method must reject this input before replacing any wallet information.
    with pytest.raises(TypeError):
        wallet.from_wif(wif=None)

    assert wallet.__dict__ == original_state
