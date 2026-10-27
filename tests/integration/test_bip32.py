"""Check HD (hierarchical deterministic) derivation against published BIP32 keys."""

import pytest

from cryptowrench.wallet import Wallet
from tests.data.bip32 import test_vectors

pytestmark = pytest.mark.integration

# Each seed has several paths to check. Build the table with ordinary loops so
# every published seed/path combination becomes a separate, clearly named case.
derivation_cases = []
for vector_number, vector in enumerate(test_vectors, start=1):
    for expected_wallet in vector["derivation_paths"]:
        derivation_path = expected_wallet["path"]
        case = pytest.param(
            vector["seed"],
            expected_wallet,
            id=f"vector-{vector_number}-{derivation_path}",
        )
        derivation_cases.append(case)


@pytest.mark.parametrize("seed_hex,expected_wallet", derivation_cases)
def test_published_bip32_vectors(seed_hex, expected_wallet):
    seed = bytes.fromhex(seed_hex)
    root_wallet = Wallet(seed=seed)
    child_wallet = root_wallet.hd_wallet(expected_wallet["path"])

    # Serialized keys include the key itself and its HD metadata. Decode the byte
    # strings to text before comparing them with the published xprv/xpub strings.
    actual_private_key = child_wallet.serialized_extended_private_key.decode()
    actual_public_key = child_wallet.serialized_extended_public_key.decode()
    assert actual_private_key == expected_wallet["expected_serialized_priv"]
    assert actual_public_key == expected_wallet["expected_serialized_pub"]
