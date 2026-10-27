"""Conflicting wallet sources must be identified and rejected as mutually exclusive."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


def test_entropy_and_mnemonic_cannot_be_combined(root_wallet, entropy):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(entropy=entropy, mnemonic=root_wallet.words)
    assert "entropy" in str(error.value)
    assert "mnemonic" in str(error.value)


def test_entropy_and_seed_cannot_be_combined(root_wallet, entropy):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(entropy=entropy, seed=root_wallet.seed)
    assert "entropy" in str(error.value)
    assert "seed" in str(error.value)


def test_entropy_and_private_key_cannot_be_combined(root_wallet, entropy):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(entropy=entropy, private_key=root_wallet.private_key)
    assert "entropy" in str(error.value)
    assert "private_key" in str(error.value)


def test_entropy_and_wif_cannot_be_combined(root_wallet, entropy):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(entropy=entropy, wif=root_wallet.wif)
    assert "entropy" in str(error.value)
    assert "wif" in str(error.value)


def test_mnemonic_and_seed_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(mnemonic=root_wallet.words, seed=root_wallet.seed)
    assert "mnemonic" in str(error.value)
    assert "seed" in str(error.value)


def test_mnemonic_and_private_key_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(mnemonic=root_wallet.words, private_key=root_wallet.private_key)
    assert "mnemonic" in str(error.value)
    assert "private_key" in str(error.value)


def test_mnemonic_and_wif_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(mnemonic=root_wallet.words, wif=root_wallet.wif)
    assert "mnemonic" in str(error.value)
    assert "wif" in str(error.value)


def test_seed_and_private_key_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(seed=root_wallet.seed, private_key=root_wallet.private_key)
    assert "seed" in str(error.value)
    assert "private_key" in str(error.value)


def test_seed_and_wif_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(seed=root_wallet.seed, wif=root_wallet.wif)
    assert "seed" in str(error.value)
    assert "wif" in str(error.value)


def test_private_key_and_wif_cannot_be_combined(root_wallet):
    """Two individually valid sources must be rejected when supplied together."""
    with pytest.raises(ValueError, match="mutually exclusive") as error:
        Wallet(private_key=root_wallet.private_key, wif=root_wallet.wif)
    assert "private_key" in str(error.value)
    assert "wif" in str(error.value)
