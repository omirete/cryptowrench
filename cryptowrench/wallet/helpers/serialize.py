import hashlib
from base58 import b58encode, BITCOIN_ALPHABET

from .keys import _compress_public_key
from .key_validation import _is_public_key_compressed, _is_valid_chain_code, _is_valid_private_key, _is_valid_public_key

PREFIXES = {
    "default": {
        "public": {
            "main": bytes.fromhex('0488B21E'), # xpub
            "test": bytes.fromhex('043587CF'), # tpub
        },
        "private": {
            "main": bytes.fromhex('0488ADE4'), # xprv
            "test": bytes.fromhex('04358394'), # tprv
        }
    },
    "44'": {
        "public": {
            "main": bytes.fromhex('0488B21E'), # xpub
            "test": bytes.fromhex('043587CF'), # tpub
        },
        "private": {
            "main": bytes.fromhex('0488ADE4'), # xprv
            "test": bytes.fromhex('04358394'), # tprv
        }
    },
    "49'": {
        "public": {
            "main": bytes.fromhex('049d7cb2'), # ypub
            "test": bytes.fromhex('044a5262'), # upub
        },
        "private": {
            "main": bytes.fromhex('049d7878'), # yprv
            "test": bytes.fromhex('044a4e28'), # uprv
        }
    },
    "84'": {
        "public": {
            "main": bytes.fromhex('04b24746'), # zpub
            "test": bytes.fromhex('045f1cf6'), # vpub
        },
        "private": {
            "main": bytes.fromhex('04b2430c'), # zprv
            "test": bytes.fromhex('045f18bc'), # vprv
        }
    },
}

def _serialization_primitive(chain_code: bytes, purpose: str, depth: int, fingerprint_parent_key: bytes, child_number: str, main_net: bool = True, private_key: bytes = None, public_key: bytes = None):
    assert (public_key != None) != (private_key != None), "Please provide either a private key or a public key."
    
    assert private_key == None or _is_valid_private_key(private_key), 'Invalid private key.'
    assert public_key == None or _is_valid_public_key(public_key), 'Invalid public key.'
    
    _validate_stock_arguments(chain_code, purpose, depth, fingerprint_parent_key, child_number, main_net)

    child_number = _parse_child_number(child_number)
    child_number = child_number.to_bytes(4, 'big')

    network = 'main' if main_net == True else 'test'
    public_or_private = "private" if private_key != None else "public"
    try:
        prefix = PREFIXES[purpose][public_or_private][network]
    except KeyError:
        prefix = PREFIXES["default"][public_or_private][network]
    
    depth = depth.to_bytes(1, 'big')
    
    serialized_key  = prefix                 # 4 bytes
    serialized_key += depth                  # 1 byte
    serialized_key += fingerprint_parent_key # 4 bytes
    serialized_key += child_number           # 4 bytes
    serialized_key += chain_code             # 32 bytes

    # Add last part (specific to private key serialization)
    if private_key != None:
        padding = b'\x00'
        last_part = padding + private_key # 33 bytes
    else:
        compressed_public_key = _get_compressed_public_key(public_key)
        last_part = compressed_public_key # 33 bytes

    serialized_key += last_part # 33 bytes

    # Add checksum
    checksum = hashlib.sha256(serialized_key).digest()
    checksum = hashlib.sha256(checksum).digest()
    serialized_key += checksum[:4]

    # Encode result
    serialized_key = b58encode(serialized_key, alphabet=BITCOIN_ALPHABET)

    return serialized_key
    

def _serialize_extended_private_key(private_key: bytes, chain_code: bytes, purpose: str, depth: int, fingerprint_parent_key: bytes, child_number: str, main_net: bool = True):
    return _serialization_primitive(
        chain_code=chain_code,
        purpose=purpose,
        depth=depth,
        fingerprint_parent_key=fingerprint_parent_key,
        child_number=str(child_number),
        main_net=main_net,
        private_key=private_key,
        public_key=None,
    )

def _serialize_extended_public_key(public_key, chain_code, purpose, depth, fingerprint_parent_key, child_number, main_net=True):
    return _serialization_primitive(
        chain_code=chain_code,
        purpose=purpose,
        depth=depth,
        fingerprint_parent_key=fingerprint_parent_key,
        child_number=str(child_number),
        main_net=main_net,
        private_key=None,
        public_key=public_key,
    )

def _validate_stock_arguments(chain_code, purpose, depth, fingerprint_parent_key, child_number, main_net):
    assert _is_valid_chain_code(chain_code), 'Invalid chain code.'
    # As per:
    # https://github.com/bitcoin/bips/blob/8a050eccbb5f9712f31d8d159e984ade0b3ffcc3/bip-0043.mediawiki#node-serialization
    # "We suggest to use always 0x0488B21E for public and 0x0488ADE4 for private
    # nodes (leading to prefixes "xpub" and "xprv" respectively).""
    # Because of this, this library won't check if the purpose is one of the
    # bunch for which special prefix bytes are available. If a purpose is not on
    # that list, we just give it the default prefixes. The following line is
    # left here for future reference.
    # assert purpose == None or purpose in list(PREFIXES.keys()), 'Purpose not suported.'
    assert isinstance(depth, int) == True, 'Depth must be a non-negative integer.'
    assert depth >= 0, 'Depth must be a non-negative integer.'
    assert isinstance(fingerprint_parent_key, bytes) == True, 'Fingerprint must be in bytes.'
    assert len(fingerprint_parent_key) == 4, 'Fingerprint must be 4 bytes.'
    if depth == 0:
        assert fingerprint_parent_key == bytes.fromhex('00000000'), 'For a master key, the fingerprint should be 0x00000000.'
    assert isinstance(child_number, str) == True, "Child number has to be a string."
    str_digits = [str(d) for d in range(10)]
    for c in str(child_number):
        assert ["'", *str_digits].count(c.lower()) > 0, f"Invalid character detected in child_number: {c}. It can only be composed of digits 0-9 and optionally an apostrophe \"'\" for hardened keys."
    assert isinstance(main_net, bool) == True, 'Main_net should be either True or False.'

def _parse_child_number(child_number: str):
    if child_number[-1] == '\'':
        # Hardened key, so add 2^31 to the value.
        return 2**31 + int(child_number[:-1])
    return int(child_number)

def _get_compressed_public_key(public_key: bytes) -> bytes:
    if _is_public_key_compressed(public_key) == True:
        return public_key
    return _compress_public_key(public_key)