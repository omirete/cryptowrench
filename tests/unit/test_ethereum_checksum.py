"""Ethereum uses mixed letter case to encode an address checksum."""

import pytest

from cryptowrench.wallet.helpers.adresses.ethereum import checksum
from tests.data.ethereum import test_ethereum_address_checksums

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("expected_address", test_ethereum_address_checksums)
def test_ethereum_checksum(expected_address):
    # These addresses have correct checksum capitalization.
    # Applying the checksum function must reproduce the exact same address.
    actual_address = checksum(expected_address)
    assert actual_address == expected_address
