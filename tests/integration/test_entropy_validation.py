"""Entropy constructor and method validation, with direct calls for each invalid option."""

import pytest

from cryptowrench.wallet import Wallet

# BIP39 permits 16, 20, 24, 28, or 32 bytes. Check all other lengths from 0 to 33.
invalid_entropy_cases = []
for byte_count in range(34):
    if byte_count not in [16, 20, 24, 28, 32]:
        case = pytest.param(bytes(byte_count), id=f"length-{byte_count}")
        invalid_entropy_cases.append(case)

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("invalid_entropy", invalid_entropy_cases)
def test_entropy_constructor_rejects_invalid_lengths(invalid_entropy):
    """Every unsupported length from 0 through 33 must be rejected."""
    with pytest.raises(ValueError):
        Wallet(entropy=invalid_entropy)


@pytest.mark.parametrize("invalid_entropy", invalid_entropy_cases)
def test_entropy_method_rejects_invalid_lengths_without_changing_wallet(
    entropy, invalid_entropy
):
    """A failed in-place import must preserve every stored wallet attribute."""
    wallet = Wallet(entropy=entropy, passphrase="original")
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    with pytest.raises(ValueError):
        wallet.from_entropy(invalid_entropy)
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param("", id="entropy-empty-text"),
        pytest.param("00" * 16, id="entropy-hex-text"),
        pytest.param(123, id="entropy-integer"),
        pytest.param([], id="entropy-list"),
        pytest.param(True, id="entropy-boolean"),
        pytest.param(bytearray(16), id="entropy-bytearray"),
        pytest.param(memoryview(bytes(16)), id="entropy-memoryview"),
    ],
)
def test_entropy_constructor_rejects_entropy_typeerror(invalid_value):
    """Reject an invalid entropy; None is covered separately as an omitted option."""
    with pytest.raises(TypeError):
        Wallet(entropy=invalid_value)


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(None, id="entropy-none"),
        pytest.param("", id="entropy-empty-text"),
        pytest.param("00" * 16, id="entropy-hex-text"),
        pytest.param(123, id="entropy-integer"),
        pytest.param([], id="entropy-list"),
        pytest.param(True, id="entropy-boolean"),
        pytest.param(bytearray(16), id="entropy-bytearray"),
        pytest.param(memoryview(bytes(16)), id="entropy-memoryview"),
    ],
)
def test_entropy_method_rejects_entropy_typeerror(entropy, invalid_value):
    """Invalid entropy must be rejected before any existing wallet state changes."""
    wallet = Wallet(entropy=entropy, passphrase="original")
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=invalid_value)
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(b"password", id="passphrase-bytes"),
        pytest.param(123, id="passphrase-integer"),
    ],
)
def test_entropy_constructor_rejects_passphrase_typeerror(entropy, invalid_value):
    """Reject an invalid passphrase; None is covered separately as an omitted option."""
    with pytest.raises(TypeError):
        Wallet(entropy=entropy, passphrase=invalid_value)


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(None, id="passphrase-none"),
        pytest.param(b"password", id="passphrase-bytes"),
        pytest.param(123, id="passphrase-integer"),
    ],
)
def test_entropy_method_rejects_passphrase_typeerror(entropy, invalid_value):
    """Invalid passphrase must be rejected before any existing wallet state changes."""
    wallet = Wallet(entropy=entropy, passphrase="original")
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=entropy, passphrase=invalid_value)
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "invalid_value",
    [pytest.param(123, id="language-integer"), pytest.param([], id="language-list")],
)
def test_entropy_constructor_rejects_language_typeerror(entropy, invalid_value):
    """Reject an invalid language; None is covered separately as an omitted option."""
    with pytest.raises(TypeError):
        Wallet(entropy=entropy, language=invalid_value)


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(None, id="language-none"),
        pytest.param(123, id="language-integer"),
        pytest.param([], id="language-list"),
    ],
)
def test_entropy_method_rejects_language_typeerror(entropy, invalid_value):
    """Invalid language must be rejected before any existing wallet state changes."""
    wallet = Wallet(entropy=entropy, passphrase="original")
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    with pytest.raises(TypeError):
        wallet.from_entropy(entropy=entropy, language=invalid_value)
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param("", id="language-empty"),
        pytest.param("unknown", id="language-unknown"),
        pytest.param("English", id="language-wrong-case"),
    ],
)
def test_entropy_constructor_rejects_language_valueerror(entropy, invalid_value):
    """Reject an invalid language; None is covered separately as an omitted option."""
    with pytest.raises(ValueError):
        Wallet(entropy=entropy, language=invalid_value)


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param("", id="language-empty"),
        pytest.param("unknown", id="language-unknown"),
        pytest.param("English", id="language-wrong-case"),
    ],
)
def test_entropy_method_rejects_language_valueerror(entropy, invalid_value):
    """Invalid language must be rejected before any existing wallet state changes."""
    wallet = Wallet(entropy=entropy, passphrase="original")
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    with pytest.raises(ValueError):
        wallet.from_entropy(entropy=entropy, language=invalid_value)
    assert wallet.__dict__ == original_state
