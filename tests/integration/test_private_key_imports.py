"""Direct private-key and extended-private-key validation examples.

A scalar is the integer represented by a key. Valid scalars range from 1 to the curve order minus 1."""

from unittest.mock import patch

import pytest

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.elliptic_math import SECP256K1_Helpers

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(bytes(32), id="zero"),
        pytest.param(SECP256K1_Helpers.order.to_bytes(32, "big"), id="order"),
        pytest.param(
            (SECP256K1_Helpers.order + 1).to_bytes(32, "big"), id="above-order"
        ),
        pytest.param((2**256 - 1).to_bytes(32, "big"), id="maximum-256-bit"),
        pytest.param(bytes(31), id="short"),
        pytest.param(bytes(33), id="long"),
    ],
)
def test_private_key_constructor_rejects_invalid_keys_before_derivation(private_key):
    """Invalid keys must fail before public-key derivation is attempted."""
    # This mock records calls; rejecting an invalid key must happen before derivation.
    with patch("cryptowrench.wallet.main.get_public_key") as derive_public_key:
        with pytest.raises(ValueError):
            Wallet(private_key=private_key)
        derive_public_key.assert_not_called()


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(bytes(32), id="zero"),
        pytest.param(SECP256K1_Helpers.order.to_bytes(32, "big"), id="order"),
        pytest.param(
            (SECP256K1_Helpers.order + 1).to_bytes(32, "big"), id="above-order"
        ),
        pytest.param((2**256 - 1).to_bytes(32, "big"), id="maximum-256-bit"),
        pytest.param(bytes(31), id="short"),
        pytest.param(bytes(33), id="long"),
    ],
)
def test_private_key_method_rejects_invalid_keys_before_derivation(private_key):
    """Invalid keys must fail before public-key derivation is attempted."""
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    # This mock records calls; rejecting an invalid key must happen before derivation.
    with patch("cryptowrench.wallet.main.get_public_key") as derive_public_key:
        with pytest.raises(ValueError):
            wallet.from_private_key(private_key=private_key)
        derive_public_key.assert_not_called()
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(bytes(32), id="zero"),
        pytest.param(SECP256K1_Helpers.order.to_bytes(32, "big"), id="order"),
        pytest.param(
            (SECP256K1_Helpers.order + 1).to_bytes(32, "big"), id="above-order"
        ),
        pytest.param((2**256 - 1).to_bytes(32, "big"), id="maximum-256-bit"),
        pytest.param(bytes(31), id="short"),
        pytest.param(bytes(33), id="long"),
    ],
)
def test_extended_private_key_constructor_rejects_invalid_keys_before_derivation(
    private_key,
):
    """Invalid keys must fail before public-key derivation is attempted."""
    # This mock records calls; rejecting an invalid key must happen before derivation.
    with patch("cryptowrench.wallet.main.get_public_key") as derive_public_key:
        with pytest.raises(ValueError):
            Wallet(private_key=private_key, chain_code=bytes(32))
        derive_public_key.assert_not_called()


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(bytes(32), id="zero"),
        pytest.param(SECP256K1_Helpers.order.to_bytes(32, "big"), id="order"),
        pytest.param(
            (SECP256K1_Helpers.order + 1).to_bytes(32, "big"), id="above-order"
        ),
        pytest.param((2**256 - 1).to_bytes(32, "big"), id="maximum-256-bit"),
        pytest.param(bytes(31), id="short"),
        pytest.param(bytes(33), id="long"),
    ],
)
def test_extended_private_key_method_rejects_invalid_keys_before_derivation(
    private_key,
):
    """Invalid keys must fail before public-key derivation is attempted."""
    wallet = Wallet(entropy=bytes(16), passphrase="original", main_net=False)
    # A shallow copy is enough: these imports replace stored values rather than mutate them.
    original_state = wallet.__dict__.copy()
    # This mock records calls; rejecting an invalid key must happen before derivation.
    with patch("cryptowrench.wallet.main.get_public_key") as derive_public_key:
        with pytest.raises(ValueError):
            wallet.from_extended_private_key(
                private_key=private_key, chain_code=bytes(32)
            )
        derive_public_key.assert_not_called()
    assert wallet.__dict__ == original_state


@pytest.mark.parametrize(
    "scalar", [1, SECP256K1_Helpers.order - 1], ids=["minimum", "maximum"]
)
def test_valid_private_key_scalar_imports(scalar):
    """The smallest and largest valid scalars import as 33-byte compressed public keys."""
    private_key = scalar.to_bytes(32, "big")
    wallet = Wallet(private_key=private_key)
    assert wallet.private_key == private_key
    assert len(wallet.public_key) == 33


@pytest.mark.parametrize(
    "scalar", [1, SECP256K1_Helpers.order - 1], ids=["minimum", "maximum"]
)
def test_valid_extended_private_key_scalar_imports(scalar):
    """Adding a chain code preserves the public key for both valid scalar boundaries."""
    private_key = scalar.to_bytes(32, "big")
    wallet = Wallet(private_key=private_key)
    extended_wallet = Wallet(private_key=private_key, chain_code=bytes(32))
    assert extended_wallet.public_key == wallet.public_key
