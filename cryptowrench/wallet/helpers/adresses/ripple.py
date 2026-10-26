from re import match
import hashlib
from base58 import b58encode_check
from typing import Optional
from enum import Enum


# The dictionary used for XRPL base58 encodings
XRPL_ALPHABET = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

# base58 encodings: https://xrpl.org/base58-encodings.html
# Account address (20 bytes)
_CLASSIC_ADDRESS_PREFIX = [0x0]

_CLASSIC_ADDRESS_LENGTH = 20

class CryptoAlgorithm(str, Enum):
    """Represents the supported cryptography algorithms."""

    ED25519 = "ed25519"
    SECP256K1 = "secp256k1"


def _encode(bytestring: bytes, prefix: list[int], expected_length: int) -> str:
    """
    Returns the base58 encoding of the bytestring, with the given data prefix
    (which indicates type) and while ensuring the bytestring is the expected
    length.
    """
    if expected_length and len(bytestring) != expected_length:
        error_message = """unexpected_payload_length: len(bytestring) does not match expected_length.
        Ensure that the bytes are a bytestring."""
        # raise XRPLAddressCodecException(error_message)
        raise Exception(error_message)
    encoded_prefix = bytes(prefix)
    payload = encoded_prefix + bytestring
    return b58encode_check(payload, alphabet=XRPL_ALPHABET).decode("utf-8")

def encode_classic_address(bytestring: bytes) -> str:
    """
    Returns the classic address encoding of these bytes as a base58 string.
    Args:
        bytestring: Bytes to be encoded.
    Returns:
        The classic address encoding of these bytes as a base58 string.
    """
    return _encode(bytestring, _CLASSIC_ADDRESS_PREFIX, _CLASSIC_ADDRESS_LENGTH)


def get_account_id(public_key: bytes) -> bytes:
    """
    Returns the account ID for a given public key. See
    https://xrpl.org/cryptographic-keys.html#account-id-and-address
    to learn about the relationship between keys and account IDs.
    Args:
        public_key: Unencoded public key.
    Returns:
        The account ID for the given public key.
    """
    sha_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha_hash).digest()
    return bytes(ripemd160_hash)

def address_ripple_classic(public_key: bytes) -> str:
    """
    Derive the XRP Ledger classic address for a given public key. See
    `Address Derivation
    <https://xrpl.org/cryptographic-keys.html#account-id-and-address>`_
    for more information.
    Args:
        public_key: The public key to derive the address from, as hexadecimal.
    Returns:
        The classic address corresponding to the given public key.
    """
    account_id = get_account_id(public_key)
    return encode_classic_address(account_id)

def validate_xrp_address(address: str) -> bool:
    # From: https://docs.trellix.com/es-ES/bundle/data-loss-prevention-11.10.x-classification-definitions-reference-guide/page/GUID-A1CFB695-32EC-4E10-B801-68E85EF51E66.html
    return match(r'\br[1-9A-HJ-NP-Za-km-z]{25,33}\b', address) != None

def derive_keypair(
    seed: str, validator: bool = False, algorithm: Optional[CryptoAlgorithm] = None
) -> tuple[str, str]:
    """
    Derive the public and private keys from a given seed value.
    Args:
        seed: Seed to derive the key pair from. Use
            :func:`generate_seed() <xrpl.core.keypairs.generate_seed>` to generate an
            appropriate value.
        validator: Whether the keypair is a validator keypair.
        algorithm: The algorithm used to encode the keys. Inferred from the seed if not
            included.
    Returns:
        A (public key, private key) pair derived from the given seed.
    Raises:
        XRPLKeypairsException: If the derived keypair did not generate a
            verifiable signature.
    """
    decoded_seed, algorithm = addresscodec.decode_seed(seed, algorithm)
    module = _ALGORITHM_TO_MODULE_MAP[algorithm]
    public_key, private_key = module.derive_keypair(decoded_seed, validator)
    signature = module.sign(_VERIFICATION_MESSAGE, private_key)
    if not module.is_valid_message(_VERIFICATION_MESSAGE, signature, public_key):
        raise XRPLKeypairsException(
            "Derived keypair did not generate verifiable signature",
        )
    return public_key, private_key