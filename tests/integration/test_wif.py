"""WIF imports recover a fixed private key, network, and compression preference."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration

EXPECTED_PRIVATE_KEY = bytes.fromhex(
    "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
)

# Each WIF encodes EXPECTED_PRIVATE_KEY with the specified network and compression.
WIF_CASES = [
    pytest.param(
        {
            "wif": "Kx2nc8CerNfcsutaet3rPwVtxQvXuQTYxw1mSsfFHsWExJ9xVpLf",
            "main_net": True,
            "compressed": True,
        },
        id="mainnet-compressed",
    ),
    pytest.param(
        {
            "wif": "5HzxC8XHHAtoC5jVvScY8Tr99Ud9MwFdF2pJKYsMTUknJZEurYr",
            "main_net": True,
            "compressed": False,
        },
        id="mainnet-uncompressed",
    ),
    pytest.param(
        {
            "wif": "cNPn53CWHSMt3MMr3HrymFzxaeDwZrZF2yAEZJ7knzAFD3GTTi2x",
            "main_net": False,
            "compressed": True,
        },
        id="testnet-compressed",
    ),
    pytest.param(
        {
            "wif": "91mamsLpsPxwA9EnYnWT14Q6o8yrX6npaygFQBDroDVq5dZG3q3",
            "main_net": False,
            "compressed": False,
        },
        id="testnet-uncompressed",
    ),
]


@pytest.mark.parametrize("wif_case", WIF_CASES)
def test_wif_constructor_settings(wif_case):
    """WIF carries its key, network, and compression preference."""
    imported_wallet = Wallet(wif=wif_case["wif"])
    assert imported_wallet.private_key == EXPECTED_PRIVATE_KEY
    assert imported_wallet.main_net == wif_case["main_net"]
    assert imported_wallet._prefer_compressed_address == wif_case["compressed"]


@pytest.mark.parametrize("wif_case", WIF_CASES)
def test_wif_constructor_failed_import(wif_case):
    """A failed import must leave the successfully imported wallet unchanged."""
    imported_wallet = Wallet(wif=wif_case["wif"])
    original_state = imported_wallet.__dict__.copy()
    with pytest.raises(ValueError):
        imported_wallet.from_wif("invalid")
    assert imported_wallet.__dict__ == original_state


@pytest.mark.parametrize("wif_case", WIF_CASES)
def test_wif_method_settings(wif_case):
    """WIF carries its key, network, and compression preference."""
    imported_wallet = Wallet()
    imported_wallet.from_wif(wif_case["wif"])
    assert imported_wallet.private_key == EXPECTED_PRIVATE_KEY
    assert imported_wallet.main_net == wif_case["main_net"]
    assert imported_wallet._prefer_compressed_address == wif_case["compressed"]


@pytest.mark.parametrize("wif_case", WIF_CASES)
def test_wif_method_failed_import(wif_case):
    """A failed import must leave the successfully imported wallet unchanged."""
    imported_wallet = Wallet()
    imported_wallet.from_wif(wif_case["wif"])
    original_state = imported_wallet.__dict__.copy()
    with pytest.raises(ValueError):
        imported_wallet.from_wif("invalid")
    assert imported_wallet.__dict__ == original_state
