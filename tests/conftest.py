"""Shared test inputs.

Pytest supplies these fixtures to tests that name them as function arguments.
Each test receives fresh inputs, so changes in one test cannot affect another.
All keys here are public test data and must never be used for real funds.
"""

from unittest.mock import patch

import pytest

from cryptowrench.wallet import Wallet


@pytest.fixture
def entropy():
    """Return 16 zero bytes: a repeatable 128-bit input for wallet creation."""
    return bytes(16)


@pytest.fixture
def root_wallet(entropy):
    """Create a known wallet whose words, keys, and seed can be imported again."""
    return Wallet(entropy=entropy)


@pytest.fixture
def deterministic_randomness():
    """Make random wallet creation repeatable for tests that compare results."""

    def return_zero_bytes(number_of_bytes):
        return bytes(number_of_bytes)

    # Patch only for this test. Leaving the with block restores real randomness.
    with patch("mnemonic.mnemonic.os.urandom", side_effect=return_zero_bytes):
        yield
