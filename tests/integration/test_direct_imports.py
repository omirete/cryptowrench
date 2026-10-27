"""Each direct import method must produce the same wallet as the constructor."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_seed_import_matches_constructor(root_wallet):
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(seed=root_wallet.seed)

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_seed(seed=root_wallet.seed)
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__


def test_mnemonic_import_matches_constructor(root_wallet):
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(mnemonic=root_wallet.words)

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_mnemonic(mnemonic=root_wallet.words)
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__


def test_entropy_import_matches_constructor():
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(entropy=bytes(16))

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_entropy(entropy=bytes(16))
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__


def test_private_key_import_matches_constructor(root_wallet):
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(private_key=root_wallet.private_key)

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_private_key(private_key=root_wallet.private_key)
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__


def test_extended_private_key_import_matches_constructor(root_wallet):
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(
        private_key=root_wallet.private_key, chain_code=root_wallet.chain_code
    )

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_extended_private_key(
        private_key=root_wallet.private_key, chain_code=root_wallet.chain_code
    )
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__


def test_wif_import_matches_constructor(root_wallet):
    # Start with a different wallet so the import must replace its previous contents.
    wallet = Wallet(entropy=bytes(32), passphrase="old")
    expected_wallet = Wallet(wif=root_wallet.wif)

    # A successful import updates the wallet in place and returns None.
    import_result = wallet.from_wif(wif=root_wallet.wif)
    assert import_result is None
    assert wallet.__dict__ == expected_wallet.__dict__
