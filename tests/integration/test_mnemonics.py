"""Mnemonic imports must produce the published BIP39 seed and master private key."""

import pytest

from cryptowrench.wallet import Wallet
from tests.data.bip39 import test_vectors_mnemonic

pytestmark = pytest.mark.integration

mnemonic_cases = []
for vector_number, vector in enumerate(test_vectors_mnemonic["english"], start=1):
    case = pytest.param(vector, id=f"bip39-{vector_number}")
    mnemonic_cases.append(case)


@pytest.mark.parametrize("vector", mnemonic_cases)
def test_mnemonic_seed_and_master_key(vector):
    # Read the published inputs and expected outputs by name.
    passphrase = vector["passphrase"]
    mnemonic_words = vector["mnemonic_words"]
    expected_seed = vector["expected_seed_hex"]
    expected_extended_private_key = vector["expected_extended_private_key"]

    wallet = Wallet(mnemonic=mnemonic_words, passphrase=passphrase)
    assert wallet.seed.hex() == expected_seed

    # The path "m" selects the master wallet without deriving any children.
    master_wallet = wallet.hd_wallet("m")
    actual_extended_private_key = master_wallet.serialized_extended_private_key.decode()
    assert actual_extended_private_key == expected_extended_private_key
