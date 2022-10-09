import hashlib
from base58 import b58decode
from .elliptic_math import SECP256K1_Helpers, _bip32_uncompress_elliptic_point

def _is_valid_private_key(private_key: bytes) -> bool:
    is_bytes = isinstance(private_key, bytes)
    length = len(private_key)
    if is_bytes == True and length == 32:
        return True
    return False

def _is_valid_wif(wif: str) -> bool:
    if isinstance(wif, str) == False:
        return False # WIF has to be entered as a string.

    WIF_MAIN_NET = bytes.fromhex('80')
    WIF_TEST_NET = bytes.fromhex('EF')
    WIF_COMPRESSION_FLAG = bytes.fromhex('01')

    # wif_before_b58_encoding is equal to private_key_and_network + checksum.
    wif_before_b58_encoding = b58decode(wif)

    length = len(wif_before_b58_encoding)
    if length != 32 + 4 + 1 and length != 33 + 4 + 1:
        return False # The WIF has an invalid length.

    # The last 4 bytes at the end are the checksum, so we drop them.
    checksum = wif_before_b58_encoding[-4:]
    private_key_and_network = wif_before_b58_encoding[:-4]

    # Check the checksum (first 4 bytes of the double sha256 of the private key and network).
    calculated_checksum = hashlib.sha256(private_key_and_network).digest()
    calculated_checksum = hashlib.sha256(calculated_checksum).digest()
    calculated_checksum = calculated_checksum[:4]

    if checksum != calculated_checksum:
        return False # Invalid checksum.

    # The first byte indicates the network (mainnet or testnet).
    network = private_key_and_network[:1]
    private_key = private_key_and_network[1:]

    if network not in [WIF_MAIN_NET, WIF_TEST_NET]:
        return False # Invalid WIF (invalid network byte).
    
    if len(private_key) == 33 and private_key[-1:] != WIF_COMPRESSION_FLAG:
        return False # Resulting private key is invalid (invalid compression byte).

    return True

def _is_valid_public_key(public_key: bytes) -> bool:

    is_bytes = isinstance(public_key, bytes)
    if is_bytes != True:
        return False # Key must be entered in bytes.
    
    length = len(public_key)
    if length != 33 and length != 65:
        return False # Invalid length.

    first_byte = public_key[0]
    if length == 65 and first_byte != 4:
        return False # For an uncompressed public key, the first byte has to be \x04.
    
    if length == 33 and first_byte != 2 and first_byte != 3:
        return False # For a compressed public key, the first byte has to be either \x02 or \x03.
    
    # Lastly, we have to check if the coordinates that conform the public key
    # lie actually on the SECP256k1 curve.
    
    if length == 33:
        P = _bip32_uncompress_elliptic_point(public_key)
        x = int.from_bytes(P[0], byteorder='big')
        y = int.from_bytes(P[1], byteorder='big')
    else:
        x = int.from_bytes(public_key[1:33], byteorder='big')
        y = int.from_bytes(public_key[33:], byteorder='big')

    return SECP256K1_Helpers().contains_point(x, y)

def _is_public_key_compressed(public_key: bytes) -> bool:

    assert _is_valid_public_key(public_key) == True, 'Invalid public key.'
    length = len(public_key)
    return True if length == 33 else False

def _is_valid_chain_code(chain_code: bytes) -> bool:
    is_bytes = isinstance(chain_code, bytes)
    length = len(chain_code)
    if is_bytes == True and length == 32:
        return True
    return False
