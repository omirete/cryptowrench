import hashlib
from base58 import b58encode

from .keys import _compress_public_key
from .key_validation import _is_public_key_compressed, _is_valid_chain_code, _is_valid_private_key, _is_valid_public_key

def _serialize_extended_private_key(private_key, chain_code, purpose, depth, fingerprint_parent_key, child_number, main_net=True):
    assert _is_valid_private_key(private_key), 'Invalid private key.'
    assert _is_valid_chain_code(chain_code), 'Invalid chain code.'
    assert purpose in ['44\'', '49\'', '84\''], 'Purpose not suported.'
    assert isinstance(depth, int) == True, 'Depth must be a non-negative integer.'
    assert depth >= 0, 'Depth must be a non-negative integer.'
    assert isinstance(fingerprint_parent_key, bytes) == True, 'Fingerprint must be in bytes.'
    assert len(fingerprint_parent_key) == 4, 'Fingerprint must be 4 bytes.'
    if isinstance(child_number, str) == True:
        if child_number[-1] == '\'':
            child_number = 2**31 + int(child_number[:-1])
    assert isinstance(child_number, int) == True, 'Child number must be a non-negative integer.'
    assert child_number >= 0, 'Depth must be a non-negative integer.'
    assert isinstance(main_net, bool) == True, 'Main_net should be either True or False.'
    
    prefix = {}
    prefix['44\''] = {}
    prefix['44\'']['main'] = bytes.fromhex('0488ADE4') # xprv
    prefix['44\'']['test'] = bytes.fromhex('04358394') # tprv
    
    prefix['49\''] = {}
    prefix['49\'']['main'] = bytes.fromhex('049d7878') # yprv
    prefix['49\'']['test'] = bytes.fromhex('044a4e28') # uprv
    
    prefix['84\''] = {}
    prefix['84\'']['main'] = bytes.fromhex('04b2430c') # zprv
    prefix['84\'']['test'] = bytes.fromhex('045f18bc') # vprv
    
    network = 'main' if main_net == True else 'test'
    
    prefix = prefix[purpose][network]
    depth = depth.to_bytes(1, 'big')
    if depth == 0:
        assert fingerprint_parent_key == bytes.fromhex('00000000'), 'For a master key, the fingerprint should be 0x00000000.'

    child_number = child_number.to_bytes(4, 'big')

    padding = b'\x00'

    serialized_key = prefix # 4 bytes
    serialized_key += depth # 1 byte
    serialized_key += fingerprint_parent_key # 4 bytes
    serialized_key += child_number # 4 bytes
    serialized_key += chain_code # 32 bytes
    serialized_key += padding + private_key # 33 bytes
    
    checksum = hashlib.sha256(serialized_key).digest()
    checksum = hashlib.sha256(checksum).digest()

    serialized_key += checksum[:4]

    serialized_key = b58encode(serialized_key)

    return serialized_key

def _serialize_extended_public_key(public_key, chain_code, purpose, depth, fingerprint_parent_key, child_number, main_net=True):
    assert _is_valid_public_key(public_key), 'Invalid public key.'
    assert _is_valid_chain_code(chain_code), 'Invalid chain code.'
    assert purpose in ['44\'', '49\'', '84\''], 'Purpose not suported.'
    assert isinstance(depth, int) == True, 'Depth must be a non-negative integer.'
    assert depth >= 0, 'Depth must be a non-negative integer.'
    assert isinstance(fingerprint_parent_key, bytes) == True, 'Fingerprint must be in bytes.'
    assert len(fingerprint_parent_key) == 4, 'Fingerprint must be 4 bytes.'
    assert isinstance(child_number, int) == True, 'Depth must be a non-negative integer.'
    assert child_number >= 0, 'Depth must be a non-negative integer.'
    assert isinstance(main_net, bool) == True, 'Main_net should be either True or False.'

    prefix = {}
    prefix['44\''] = {}
    prefix['44\'']['main'] = bytes.fromhex('0488B21E') # xpub
    prefix['44\'']['test'] = bytes.fromhex('043587CF') # tpub

    prefix['49\''] = {}
    prefix['49\'']['main'] = bytes.fromhex('049d7cb2') # ypub
    prefix['49\'']['test'] = bytes.fromhex('044a5262') # upub
    
    prefix['84\''] = {}
    prefix['84\'']['main'] = bytes.fromhex('04b24746') # zpub
    prefix['84\'']['test'] = bytes.fromhex('045f1cf6') # vpub
    
    network = 'main' if main_net == True else 'test'
    
    prefix = prefix[purpose][network]
    depth = depth.to_bytes(1, 'big')
    if depth == 0:
        assert fingerprint_parent_key == bytes.fromhex('00000000'), 'For a master key, the fingerprint should be 0x00000000.'
    child_number = child_number.to_bytes(4, 'big')

    serialized_key = prefix
    serialized_key += depth
    serialized_key += fingerprint_parent_key
    serialized_key += child_number
    serialized_key += chain_code

    if _is_public_key_compressed(public_key) == True:
        serialized_key += public_key
    else:
        serialized_key += _compress_public_key(public_key)

    checksum = hashlib.sha256(serialized_key).digest()
    checksum = hashlib.sha256(checksum).digest()

    serialized_key += checksum[:4]

    serialized_key = b58encode(serialized_key)

    return serialized_key
