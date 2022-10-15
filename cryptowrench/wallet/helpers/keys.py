from __future__ import annotations
import hmac, hashlib
from base58 import b58encode, b58decode, BITCOIN_ALPHABET
from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1, derive_private_key

from .key_validation import _is_public_key_compressed, _is_valid_private_key, _is_valid_public_key, _is_valid_wif

class ExtendedPrivateKey():
    def __init__(self, private_key: bytes, chain_code: bytes, parent: ExtendedPrivateKey = None) -> None:
        self.private_key = private_key
        self.chain_code  = chain_code
        self.parent = parent

def get_private_key_and_chain_code_from_seed(seed) -> ExtendedPrivateKey:
    # See:
    #   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation
    #   https://learnmeabitcoin.com/technical/extended-keys
    assert isinstance(seed, bytes) == True, 'The seed has to be provided as bytes.'
    hmac_result = hmac.new(b'Bitcoin seed', seed, digestmod=hashlib.sha512).digest()
    priv_key = hmac_result[:32]
    chain_code = hmac_result[32:]
    return ExtendedPrivateKey(priv_key, chain_code)

def get_public_key(private_key: bytes, compressed: bool = True) -> bytes:
    # From: https://developer.bitcoin.org/devguide/wallets.html?highlight=public
    # Bitcoin Core uses several different identifier bytes to help programs
    # identify how keys should be used:
    #
    #   - Private keys meant to be used with compressed public keys have 0x01
    #   appended to them before being Base-58 encoded.
    #
    #   - Uncompressed public keys start with 0x04; compressed public keys begin
    #   with 0x03 or 0x02 depending on whether they’re greater or less than the
    #   midpoint of the curve. These prefix bytes are all used in official
    #   secp256k1 documentation (see point 2.3.3 at 
    #   https://www.secg.org/sec1-v2.pdf).
    #
    # Also helpful: https://www.royalfork.org/2014/07/31/address-gen/
    #
    #   - "Why must the 2 y coordinates have unique parity? Because the elliptic
    #   curve is over a prime finite field, when we change sign, we flip parity.
    #   Illustrated simply, 5 modulus 7 = 5 is odd, but -5 modulus 7 = 2, which
    #   is even".
    assert _is_valid_private_key(private_key) == True, 'Invalid private key.'
    assert isinstance(compressed, bool) == True, 'The "compressed" argument must be either True or False.'

    private_key_elliptic_curve = derive_private_key(
        private_value=int.from_bytes(private_key, 'big'),
        curve=SECP256K1())
    
    point = private_key_elliptic_curve.public_key().public_numbers()
    
    x = point.x.to_bytes(32, 'big').hex()
    y = point.y.to_bytes(32, 'big').hex()

    if compressed == True:
        prefix = '02' if int(y, 16) % 2 == 0 else '03'
        public_key_hex = prefix + x
    else:
        prefix = '04'
        public_key_hex = prefix + x + y

    return bytes.fromhex(public_key_hex)

def _compress_public_key(public_key_as_bytes) -> bytes:
    assert _is_valid_public_key(public_key_as_bytes), 'Invalid public key'
    if _is_public_key_compressed(public_key_as_bytes) == True:
        return public_key_as_bytes
    else:
        x = public_key_as_bytes[1:33]
        y = public_key_as_bytes[33:]
        y_int = int.from_bytes(y, byteorder='big')

        prefix_even = b'\02'
        prefix_odd = b'\03'
        
        prefix = prefix_even if y_int % 2 == 0 else prefix_odd

        return prefix + x

def get_wif_from_private_key(private_key: bytes, main_net: bool = True, generate_compressed: bool = True) -> str:
    
    assert _is_valid_private_key(private_key) == True, 'Invalid private key.'
    assert isinstance(main_net, bool) == True, 'The \'main_net\' argument must be either True or False.'
    assert isinstance(generate_compressed, bool) == True, 'The \'generate_compressed\' argument must be either True or False.'

    # Generate WIF as per:
    # https://en.bitcoin.it/wiki/Wallet_import_format
    
    WIF_MAIN_NET = bytes.fromhex('80')
    WIF_TEST_NET = bytes.fromhex('EF')
    WIF_COMPRESSION_FLAG = bytes.fromhex('01')

    # See: https://www.royalfork.org/2014/07/31/address-gen/
    network = WIF_MAIN_NET if main_net == True else WIF_TEST_NET
    private_key_and_network = network + private_key
    if generate_compressed == True:
        private_key_and_network += WIF_COMPRESSION_FLAG
    
    # Compute checksum
    hash_1 = hashlib.sha256(private_key_and_network).digest()
    hash_2 = hashlib.sha256(hash_1).digest()
    checksum = hash_2[:4]
    
    wif_before_b58_encoding = private_key_and_network + checksum
    wif = str(b58encode(wif_before_b58_encoding, alphabet=BITCOIN_ALPHABET), encoding='utf-8')

    return wif

def get_private_key_from_wif(wif: str) -> tuple[bytes, bool, bool]:
    """
    If a valid wif is provided, it returns the following tuple:
    (private_key, main_net, use_with_compressed_public_key)
    """

    if _is_valid_wif(wif) == False:
        raise ValueError("Invalid wif.")

    main_net = True
    compressed_pubkey = False
    if wif[0] == "c" or  wif[0] == "9":
        main_net = False
    if wif[0] == "K" or wif[0] == "L":
        compressed_pubkey = True
    if wif[0] == "M": # For legacy Electrum wallets
        compressed_pubkey = True
    if wif[0] == "c": # For test net
        compressed_pubkey = True
    
    wif_bytes = b58decode(wif, alphabet=BITCOIN_ALPHABET)
    wif_bytes_no_checksum = wif_bytes[:-4]
    wif_bytes_no_checksum_and_no_first_byte = wif_bytes_no_checksum[1:]
    if compressed_pubkey == True:
        private_key = wif_bytes_no_checksum_and_no_first_byte[:-1]
    else:
        private_key = wif_bytes_no_checksum_and_no_first_byte

    return (private_key, compressed_pubkey, main_net)
