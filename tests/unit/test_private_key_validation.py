"""Check the private-key validator directly, without creating a Wallet.

A valid key is exactly 32 bytes and represents an integer from 1 to order - 1.
The curve order is the upper limit used by the secp256k1 cryptographic algorithm.
"""

import pytest

from cryptowrench.wallet.helpers.elliptic_math import SECP256K1_Helpers
from cryptowrench.wallet.helpers.key_validation import _is_valid_private_key

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "scalar",
    [
        pytest.param(0, id="zero"),
        pytest.param(SECP256K1_Helpers.order, id="order"),
        pytest.param(SECP256K1_Helpers.order + 1, id="above-order"),
        pytest.param(2**256 - 1, id="maximum-256-bit"),
    ],
)
def test_invalid_scalars(scalar):
    # All these integers fit into 32 bytes, but lie outside the valid key range.
    private_key = scalar.to_bytes(32, "big")
    is_valid = _is_valid_private_key(private_key)
    assert not is_valid


@pytest.mark.parametrize(
    "invalid_key",
    [
        pytest.param(None, id="none"),
        pytest.param(1, id="integer"),
        pytest.param(True, id="boolean"),
        pytest.param("0" * 32, id="text"),
        pytest.param([], id="list"),
        pytest.param(bytearray(32), id="bytearray"),
        pytest.param(memoryview(bytes(32)), id="memoryview"),
        pytest.param(b"", id="empty"),
        pytest.param(bytes(16), id="16-bytes"),
        pytest.param(bytes(31), id="31-bytes"),
        pytest.param(bytes(33), id="33-bytes"),
    ],
)
def test_invalid_types_and_lengths_return_false(invalid_key):
    # Byte-like containers are not accepted: the validator requires actual bytes.
    # Invalid inputs must return False rather than raise an exception.
    is_valid = _is_valid_private_key(invalid_key)
    assert not is_valid


@pytest.mark.parametrize(
    "scalar",
    [
        pytest.param(1, id="minimum"),
        pytest.param(SECP256K1_Helpers.order - 1, id="maximum"),
    ],
)
def test_valid_scalar_boundaries(scalar):
    # Check the smallest and largest allowed values, including leading zero bytes.
    private_key = scalar.to_bytes(32, "big")
    is_valid = _is_valid_private_key(private_key)
    assert is_valid
