"""Entropy is raw input bytes used to create mnemonic words and then a wallet seed.

These checks cover the published BIP39 examples, supported input lengths and
languages, passphrases, and invalid inputs. No real funds should use these values.
"""

from unittest.mock import patch

import pytest
from mnemonic import Mnemonic

from cryptowrench.wallet import Wallet
from tests.data.bip39 import test_vectors_mnemonic

pytestmark = pytest.mark.integration
# Prepare named cases from published data; no wallets are created during collection.
bip39_cases = []
for vector_number, vector in enumerate(test_vectors_mnemonic["english"], start=1):
    case = pytest.param(vector, id=f"bip39-{vector_number}")
    bip39_cases.append(case)


@pytest.mark.parametrize("vector", bip39_cases)
def test_entropy_constructor_matches_published_bip39_vectors(vector):
    """Use every published entropy example to check words, passphrase, seed, and master key."""
    passphrase = vector["passphrase"]
    entropy = bytes.fromhex(vector["entropy_hex"])
    expected_words = vector["mnemonic_words"]
    expected_seed = vector["expected_seed_hex"]
    expected_extended_private_key = vector["expected_extended_private_key"]
    wallet = Wallet(entropy=entropy, passphrase=passphrase)
    assert wallet.words == expected_words
    assert wallet.passphrase == passphrase
    assert wallet.seed.hex() == expected_seed
    master_wallet = wallet.hd_wallet("m")
    assert (
        master_wallet.serialized_extended_private_key.decode()
        == expected_extended_private_key
    )


@pytest.mark.parametrize("vector", bip39_cases)
def test_entropy_method_matches_published_bip39_vectors(vector):
    """Use every published entropy example to check words, passphrase, seed, and master key."""
    passphrase = vector["passphrase"]
    entropy = bytes.fromhex(vector["entropy_hex"])
    expected_words = vector["mnemonic_words"]
    expected_seed = vector["expected_seed_hex"]
    expected_extended_private_key = vector["expected_extended_private_key"]
    wallet = Wallet(seed=bytes(range(16)))
    import_result = wallet.from_entropy(entropy, passphrase)
    assert import_result is None
    assert wallet.words == expected_words
    assert wallet.passphrase == passphrase
    assert wallet.seed.hex() == expected_seed
    master_wallet = wallet.hd_wallet("m")
    assert (
        master_wallet.serialized_extended_private_key.decode()
        == expected_extended_private_key
    )


@pytest.mark.parametrize("language", Mnemonic.list_languages())
def test_entropy_constructor_uses_selected_language(entropy, language):
    """Selected language must be used directly; calling automatic detection fails this test."""
    # Fail immediately if the implementation tries to detect a language automatically.
    with patch.object(
        Mnemonic,
        "detect_language",
        side_effect=AssertionError("Must use selected language"),
    ):
        wallet = Wallet(
            entropy=entropy, passphrase="TREZOR", language=language, main_net=False
        )
    expected_words = Mnemonic(language).to_mnemonic(entropy)
    expected_seed = Mnemonic.to_seed(expected_words, "TREZOR")
    assert wallet.words == expected_words
    assert Mnemonic(language).check(wallet.words)
    assert wallet.seed == expected_seed
    assert wallet.test_net


@pytest.mark.parametrize("language", Mnemonic.list_languages())
def test_entropy_method_uses_selected_language(entropy, language):
    """Selected language must be used directly; calling automatic detection fails this test."""
    wallet = Wallet(seed=bytes(range(16)), main_net=False)
    # Fail immediately if the implementation tries to detect a language automatically.
    with patch.object(
        Mnemonic,
        "detect_language",
        side_effect=AssertionError("Must use selected language"),
    ):
        wallet.from_entropy(entropy, "TREZOR", language)
    expected_words = Mnemonic(language).to_mnemonic(entropy)
    expected_seed = Mnemonic.to_seed(expected_words, "TREZOR")
    assert wallet.words == expected_words
    assert Mnemonic(language).check(wallet.words)
    assert wallet.seed == expected_seed
    assert wallet.test_net


@pytest.mark.parametrize(
    "bits,expected_word_count", [(128, 12), (160, 15), (192, 18), (224, 21), (256, 24)]
)
def test_all_entropy_lengths_and_leading_zeros(bits, expected_word_count):
    """Zero-filled entropy must round-trip through words and determine the word count."""
    entropy = bytes(bits // 8)
    wallet = Wallet(entropy=entropy)
    assert len(wallet.words.split()) == expected_word_count
    recovered_entropy = Mnemonic("english").to_entropy(wallet.words)
    assert recovered_entropy == entropy
    imported_wallet = Wallet(mnemonic=wallet.words)
    assert wallet.seed == imported_wallet.seed


@pytest.mark.parametrize(
    "entropy",
    [
        pytest.param(bytes(range(16)), id="binary-range"),
        pytest.param(b"0123456789abcdef", id="ascii"),
        pytest.param(b"\xff" * 16, id="high-bytes"),
        pytest.param(b"\x00\t\n\r " + bytes(range(11)), id="whitespace"),
    ],
)
def test_raw_bytes_are_not_decoded_as_text_or_hex(entropy):
    """Recover every original entropy byte, including whitespace and leading zeros."""
    wallet = Wallet(entropy=entropy)
    recovered_entropy = Mnemonic("english").to_entropy(wallet.words)
    assert recovered_entropy == entropy


@pytest.mark.parametrize("strength", [128, 160, 192, 224, 256, 1])
def test_strength_and_entropy_are_mutually_exclusive(entropy, strength):
    """Explicit entropy determines strength; supplying both is rejected."""
    with pytest.raises(ValueError, match="'entropy' and 'strength'"):
        Wallet(entropy=entropy, strength=strength)


def test_entropy_determines_word_count():
    """32 entropy bytes contain 256 bits, represented by 24 mnemonic words."""
    wallet = Wallet(entropy=bytes(32))
    assert len(wallet.words.split()) == 24


def test_empty_passphrase_matches_default(entropy):
    """Omitting the passphrase is equivalent to passing an empty string."""
    default_wallet = Wallet(entropy=entropy)
    empty_passphrase_wallet = Wallet(entropy=entropy, passphrase="")
    assert default_wallet.seed == empty_passphrase_wallet.seed


def test_passphrase_changes_seed_but_preserves_words(entropy):
    """A passphrase changes the seed, while entropy still determines the words."""
    default_wallet = Wallet(entropy=entropy)
    protected_wallet = Wallet(entropy=entropy, passphrase="TREZOR")
    assert default_wallet.seed != protected_wallet.seed
    assert default_wallet.words == protected_wallet.words


def test_equivalent_unicode_passphrases_produce_same_seed(entropy):
    """Composed and decomposed spellings of an accented e are normalized by BIP39."""
    composed_wallet = Wallet(entropy=entropy, passphrase="caf\u00e9")
    decomposed_wallet = Wallet(entropy=entropy, passphrase="cafe\u0301")
    assert composed_wallet.seed == decomposed_wallet.seed


def test_entropy_constructor_uses_japanese_word_separator(entropy):
    """Japanese mnemonic words must use the ideographic space U+3000."""
    # Fail immediately if the implementation tries to detect a language automatically.
    with patch.object(
        Mnemonic,
        "detect_language",
        side_effect=AssertionError("Must use selected language"),
    ):
        wallet = Wallet(
            entropy=entropy, passphrase="TREZOR", language="japanese", main_net=False
        )
    assert "\u3000" in wallet.words


def test_entropy_method_uses_japanese_word_separator(entropy):
    """Japanese mnemonic words must use the ideographic space U+3000."""
    wallet = Wallet(seed=bytes(range(16)), main_net=False)
    # Fail immediately if the implementation tries to detect a language automatically.
    with patch.object(
        Mnemonic,
        "detect_language",
        side_effect=AssertionError("Must use selected language"),
    ):
        wallet.from_entropy(entropy, "TREZOR", "japanese")
    assert "\u3000" in wallet.words
