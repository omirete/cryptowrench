"""Direct import examples preserving keys and HD addresses."""

import pytest
from mnemonic import Mnemonic

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_mnemonic_import_preserves_keys_and_hd_address(entropy):
    """Reimport the same source and verify its keys and derived Bitcoin address."""
    original_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    imported_wallet = Wallet(mnemonic=original_wallet.words, passphrase="TREZOR")
    assert imported_wallet.private_key == original_wallet.private_key
    assert imported_wallet.chain_code == original_wallet.chain_code
    derivation_path = "m/84'/0'/0'/0/0"
    imported_child = imported_wallet.hd_wallet(derivation_path)
    original_child = original_wallet.hd_wallet(derivation_path)
    assert (
        imported_child.address.bitcoin.P2WPKH_wit0
        == original_child.address.bitcoin.P2WPKH_wit0
    )


def test_seed_import_preserves_keys_and_hd_address(entropy):
    """Reimport the same source and verify its keys and derived Bitcoin address."""
    original_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    imported_wallet = Wallet(seed=original_wallet.seed)
    assert imported_wallet.private_key == original_wallet.private_key
    assert imported_wallet.chain_code == original_wallet.chain_code
    derivation_path = "m/84'/0'/0'/0/0"
    imported_child = imported_wallet.hd_wallet(derivation_path)
    original_child = original_wallet.hd_wallet(derivation_path)
    assert (
        imported_child.address.bitcoin.P2WPKH_wit0
        == original_child.address.bitcoin.P2WPKH_wit0
    )


def test_extended_private_key_import_preserves_keys_and_hd_address(entropy):
    """Reimport the same source and verify its keys and derived Bitcoin address."""
    original_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    imported_wallet = Wallet(
        private_key=original_wallet.private_key, chain_code=original_wallet.chain_code
    )
    assert imported_wallet.private_key == original_wallet.private_key
    assert imported_wallet.chain_code == original_wallet.chain_code
    derivation_path = "m/84'/0'/0'/0/0"
    imported_child = imported_wallet.hd_wallet(derivation_path)
    original_child = original_wallet.hd_wallet(derivation_path)
    assert (
        imported_child.address.bitcoin.P2WPKH_wit0
        == original_child.address.bitcoin.P2WPKH_wit0
    )


def test_private_key_import_has_no_chain_code(entropy):
    """This format contains a private key but no chain code for HD derivation."""
    original_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    imported_wallet = Wallet(private_key=original_wallet.private_key)
    assert imported_wallet.private_key == original_wallet.private_key
    assert imported_wallet.chain_code is None


def test_wif_import_has_no_chain_code(entropy):
    """This format contains a private key but no chain code for HD derivation."""
    original_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    imported_wallet = Wallet(wif=original_wallet.wif)
    assert imported_wallet.private_key == original_wallet.private_key
    assert imported_wallet.chain_code is None


def test_invalid_wif_is_rejected():
    """Arbitrary text is not a valid checksummed WIF private key."""
    with pytest.raises(ValueError):
        Wallet(wif="invalid")


@pytest.mark.parametrize("language", Mnemonic.list_languages())
def test_random_wallet_language(language):
    """Random creation must use the selected word list and passphrase to derive its seed."""
    wallet = Wallet(strength=160, passphrase="test", language=language)
    assert Mnemonic(language).check(wallet.words)
    expected_seed = Mnemonic.to_seed(wallet.words, "test")
    assert wallet.seed == expected_seed
