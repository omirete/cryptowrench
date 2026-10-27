"""Explicit examples of extended-key metadata requirements."""

import pytest

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.derivation_path import DerivationPath

pytestmark = pytest.mark.integration


def test_random_creation_rejects_both_metadata():
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(derivation_path=DerivationPath("m"), fingerprint_parent_key=bytes(4))


def test_random_creation_rejects_path_only_metadata():
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(derivation_path=DerivationPath("m"))


def test_random_creation_rejects_fingerprint_only_metadata():
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(fingerprint_parent_key=bytes(4))


def test_entropy_creation_rejects_both_metadata(entropy):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(
            entropy=entropy,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(4),
        )


def test_entropy_creation_rejects_path_only_metadata(entropy):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(entropy=entropy, derivation_path=DerivationPath("m"))


def test_entropy_creation_rejects_fingerprint_only_metadata(entropy):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(entropy=entropy, fingerprint_parent_key=bytes(4))


def test_mnemonic_creation_rejects_both_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(
            mnemonic=root_wallet.words,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(4),
        )


def test_mnemonic_creation_rejects_path_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(mnemonic=root_wallet.words, derivation_path=DerivationPath("m"))


def test_mnemonic_creation_rejects_fingerprint_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(mnemonic=root_wallet.words, fingerprint_parent_key=bytes(4))


def test_seed_creation_rejects_both_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(
            seed=root_wallet.seed,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(4),
        )


def test_seed_creation_rejects_path_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(seed=root_wallet.seed, derivation_path=DerivationPath("m"))


def test_seed_creation_rejects_fingerprint_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(seed=root_wallet.seed, fingerprint_parent_key=bytes(4))


def test_private_key_creation_rejects_both_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(
            private_key=root_wallet.private_key,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(4),
        )


def test_private_key_creation_rejects_path_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(private_key=root_wallet.private_key, derivation_path=DerivationPath("m"))


def test_private_key_creation_rejects_fingerprint_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(private_key=root_wallet.private_key, fingerprint_parent_key=bytes(4))


def test_wif_creation_rejects_both_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(
            wif=root_wallet.wif,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(4),
        )


def test_wif_creation_rejects_path_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(wif=root_wallet.wif, derivation_path=DerivationPath("m"))


def test_wif_creation_rejects_fingerprint_only_metadata(root_wallet):
    """Metadata requires both an explicit private key and a chain code."""
    with pytest.raises(ValueError):
        Wallet(wif=root_wallet.wif, fingerprint_parent_key=bytes(4))


def test_extended_key_metadata_requires_fingerprint(root_wallet):
    """An extended key import must supply both metadata fields together."""
    with pytest.raises(ValueError, match="together"):
        Wallet(
            private_key=root_wallet.private_key,
            chain_code=root_wallet.chain_code,
            derivation_path=DerivationPath("m"),
        )


def test_extended_key_metadata_requires_path(root_wallet):
    """An extended key import must supply both metadata fields together."""
    with pytest.raises(ValueError, match="together"):
        Wallet(
            private_key=root_wallet.private_key,
            chain_code=root_wallet.chain_code,
            fingerprint_parent_key=bytes(4),
        )


@pytest.mark.parametrize("size", [0, 3, 5], ids=["empty", "too-short", "too-long"])
def test_fingerprint_requires_four_bytes(root_wallet, size):
    """Keep the key and path valid; only the fingerprint length is invalid."""
    with pytest.raises(ValueError, match="four bytes"):
        Wallet(
            private_key=root_wallet.private_key,
            chain_code=root_wallet.chain_code,
            derivation_path=DerivationPath("m"),
            fingerprint_parent_key=bytes(size),
        )


def test_root_metadata_preserves_extended_private_key(root_wallet):
    """Importing metadata for m must reproduce the root extended private key."""
    imported_wallet = Wallet(
        private_key=root_wallet.private_key,
        chain_code=root_wallet.chain_code,
        derivation_path=DerivationPath("m"),
        fingerprint_parent_key=bytes(4),
    )
    expected_master_wallet = root_wallet.hd_wallet("m")
    assert (
        imported_wallet.serialized_extended_private_key
        == expected_master_wallet.serialized_extended_private_key
    )


def test_bip84_child_has_expected_depth_and_public_key_prefix(root_wallet):
    """The BIP84 child path has five levels and uses the zpub prefix."""
    child_wallet = root_wallet.hd_wallet("m/84'/0'/0'/0/0")
    assert child_wallet.derivation_path.depth == 5
    assert child_wallet.serialized_extended_public_key.startswith(b"zpub")
