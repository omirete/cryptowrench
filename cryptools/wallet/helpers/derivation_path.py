import hashlib, hmac
from re import match
from ecdsa import SECP256k1, ellipticcurve
from ecdsa.ecdsa import curve_secp256k1

from .elliptic_math import _bip32_point, _bip32_serialize_point, _bip32_uncompress_elliptic_point
from .key_validation import _is_public_key_compressed, _is_valid_chain_code, _is_valid_private_key, _is_valid_public_key
from .keys import _compress_public_key, get_public_key 
from .serialize import _serialize_extended_private_key, _serialize_extended_public_key
from .hashfuncs import get_hash160


class DerivationPath():
    def __init__(self, path: str) -> None:
        assert isinstance(path, str), "The path should be a string. Example: m/44'/0'/0'/0/0"
        path = path.replace(' ', '')
        
        path_pattern = r"(?P<path>^(?P<key_type>[m|M])(?:\/(?P<purpose>(?:0|[1-9][0-9]*)['])(?:\/(?P<coin_type>(?:0|[1-9][0-9]*)['])(?:\/(?P<account>(?:0|[1-9][0-9]*)['])(?:\/(?P<change>[01])(?:\/(?P<address_index>(?:0|[1-9][0-9]*)[']?))?)?)?)?)?)"
        match_results = match(path_pattern, path)
        assert match_results != None, "Could not parse derivation path. Make sure it is valid. Example: m/44'/0'/0'/0/0"
        
        path_dict = match_results.groupdict()
        assert path_dict['path'] == path, "Could not parse derivation path. Make sure it is valid. Example: m/44'/0'/0'/0/0"
        
        self.key_type = path_dict['key_type']
        self.purpose = path_dict['purpose']
        self.coin_type = path_dict['coin_type']
        self.account = path_dict['account']
        self.change = path_dict['change']
        self.address_index = path_dict['address_index']

def derive_wallet(derivation_path: str, master_private_key: bytes, master_chain_code: bytes, flag_compress_public_keys: bool = True, main_net: bool = True):
    
    '''
    From: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

    # Path scheme: m / purpose' / coin_type' / account' / change / address_index

    #Purpose
    Purpose is a constant and it indicates the specification for which the
    subtree of this node is to be used. Hardened derivation is used at this
    level.
    
    # Coin type
    Coin type is a constant, set for each cryptocoin.

    # Account
    This level splits the key space into independent user identities, so the
    wallet never mixes the coins across different accounts.
    Accounts are numbered from index 0 in sequentially increasing manner.
    Hardened derivation is used at this level.
    Software should prevent a creation of an account if a previous account does
    not have a transaction history (meaning none of its addresses have been used
    before).
    
    # Change
    Constant 0 is used for external chain and constant 1 for internal chain
    (also known as change addresses). External chain is used for addresses that
    are meant to be visible outside of the wallet (e.g. for receiving payments).
    Internal chain is used for addresses which are not meant to be visible
    outside of the wallet and is used for return transaction change.
    Public derivation is used at this level.

    # Index
    Addresses are numbered from index 0 in sequentially increasing manner. 
    Public derivation is used at this level. 
    '''
    assert _is_valid_private_key(master_private_key) == True, 'Invalid private key.'
    
    path_details = DerivationPath(derivation_path)
    
    key_type = path_details.key_type
    purpose = path_details.purpose
    coin_type = path_details.coin_type
    account = path_details.account
    change = path_details.change
    address_index = path_details.address_index

    supported_coins = {
        "bitcoin": "0'",
        "ethereum": "60'"
    }

    assert coin_type in supported_coins.values() or coin_type == None, 'Coin not suported.'
    
    # The "[:-1]" part removes the apostrophe (for example: 0' -> 0).
    coin_type = None if coin_type == None else (2**31 + int(coin_type[:-1]))
    account = None if account == None else (2**31 + int(account[:-1]))
    change = None if change == None else int(change)
    address_index = None if address_index is None else int(address_index)

    # 'm' is for private key, and 'M' is for public key.
    if key_type == 'm':
        key_depth_0 = master_private_key
        derivation_function = ChildKeyDerivation_private
        serialization_function = _serialize_extended_private_key
    else:
        key_depth_0 =  get_public_key(
            private_key_as_bytes=master_private_key,
            compressed=flag_compress_public_keys)
        derivation_function = ChildKeyDerivation_public
        serialization_function = _serialize_extended_public_key
    
    current_key = key_depth_0
    current_chain_code = master_chain_code
    index = 0

    # Path scheme: m / purpose' / coin_type' / account' / change / address_index
    
    derivation_index_secuence = (purpose, coin_type, account, change, address_index)
    depth = 0

    for next_index in derivation_index_secuence:
        if next_index == None:
            break
        else:
            depth += 1
            last_key = current_key
            last_chain_code = current_chain_code
            index = next_index
            current_key, current_chain_code = derivation_function(
                last_key,
                parent_chain_code_as_bytes=last_chain_code,
                i=index)
    
    if depth == 0:
        fingerprint_parent_key = bytes.fromhex('00000000')
    else:
        last_public_key_compressed = get_public_key(
            private_key=last_key,
            compressed=True) # Must be compressed (serialized), as per BIP32.
        fingerprint_parent_key = get_hash160(last_public_key_compressed)
        fingerprint_parent_key = fingerprint_parent_key[:4] # Fingerprint
    
    serialized_key = serialization_function(
        current_key,
        current_chain_code,
        purpose=purpose,
        depth=depth,
        fingerprint_parent_key=fingerprint_parent_key,
        child_number=index,
        main_net=True)
    
    return current_key, current_chain_code, serialized_key

def ChildKeyDerivation_private(parent_private_key_as_bytes, parent_chain_code_as_bytes, i):
    
    assert _is_valid_private_key(parent_private_key_as_bytes) == True, 'Invalid private key.'
    assert _is_valid_chain_code(parent_chain_code_as_bytes) == True, 'Invalid chain code.'
    if isinstance(i, str) == True:
        if i[-1] == '\'':
            i = 2**31 + int(i[:-1])
    assert isinstance(i, int) == True, 'Index \'i\' must be an integer, or an integer with an apostrophe at the end.'
    assert i >= 0 and i <= 2**32-1, 'Index must be between 0 and 2^32-1.'

    serialized_i = i.to_bytes(length=4, byteorder='big')

    if i >= 2**31:
        # The child key is a hardened key (hardened child).
        padding = b'\x00'
        data = padding + parent_private_key_as_bytes + serialized_i
    else:
        # The child key is NOT a hardened key (normal child).
        P = _bip32_point(parent_private_key_as_bytes)
        serialized_P = _bip32_serialize_point(P)
        data = serialized_P + serialized_i

    I = hmac.new(
        key=parent_chain_code_as_bytes,
        msg=data,
        digestmod=hashlib.sha512).digest()

    I_L = I[:32]
    I_R = I[32:]

    parent_private_key_as_int = int.from_bytes(
        parent_private_key_as_bytes,
        byteorder='big')
    n = SECP256k1.order
    
    I_L_as_int = int.from_bytes(I_L, byteorder='big')
    child_private_key_as_int = (I_L_as_int + parent_private_key_as_int) % n
    if I_L_as_int >= n or child_private_key_as_int == 0:
        raise IndexError('The key derived from that index is invalid. Increase the index by 1.')
    else:
        child_private_key = child_private_key_as_int.to_bytes(
            length=32,
            byteorder='big')
        
        child_chain_code = I_R

        return child_private_key, child_chain_code

def ChildKeyDerivation_public(parent_pubKey_as_bytes, parent_chain_code_as_bytes, i, return_compressed=True):
    
    assert _is_valid_public_key(parent_pubKey_as_bytes) == True, 'Invalid public key.'
    if _is_public_key_compressed(parent_pubKey_as_bytes) == False:
        parent_pubKey_as_bytes = _compress_public_key(
            parent_pubKey_as_bytes)
    assert _is_valid_chain_code(parent_chain_code_as_bytes) == True, 'Invalid chain code.'
    if isinstance(i, str) == True:
        if i[-1] == '\'':
            i = 2**31 + int(i[:-1])
    assert isinstance(i, int) == True, 'Index \'i\' must be an integer, or an integer with an apostrophe at the end.'
    assert i >= 0 and i <= 2**32-1, 'Index must be between 0 and 2^32-1.'

    serialized_i = i.to_bytes(length=4, byteorder='big')
    parent_public_key_coords = _bip32_uncompress_elliptic_point(
        compressed_point_as_bytes=parent_pubKey_as_bytes)

    if i >= 2**31:
        # The specification does not allow for this case.
        raise IndexError('Derived public key index must be i < 2^31')
    else:
        # The child key is NOT a hardened key (normal child).
        data = parent_pubKey_as_bytes + serialized_i

    I = hmac.new(
        key=parent_chain_code_as_bytes,
        msg=data,
        digestmod=hashlib.sha512).digest()

    I_L = I[:32]
    I_R = I[32:]

    parent_public_key_as_int = int.from_bytes(
        bytes=parent_pubKey_as_bytes,
        byteorder='big')
    n = SECP256k1.order
    
    I_L_as_int = int.from_bytes(I_L, byteorder='big')
    
    if I_L_as_int >= n:
        raise IndexError('The key derived from that index is invalid. Increase the index by 1.')
    else:
        elliptic_point_from_I_L_int = I_L_as_int * SECP256k1.generator
        elliptic_point_from_parent_Key = ellipticcurve.Point(
            curve=curve_secp256k1,
            x=int.from_bytes(parent_public_key_coords[0], 'big'),
            y=int.from_bytes(parent_public_key_coords[1], 'big'),
            order=SECP256k1.order)
        
        # Check if the result is "the point at infinity".
        # The point at infinity occurs when two points such as P1 and P2 (see
        # below) are added.
        # P1 = (x, y)
        # P2 = (x, -y)

        if elliptic_point_from_I_L_int.x() == elliptic_point_from_parent_Key.x():
            if elliptic_point_from_I_L_int.y() == -elliptic_point_from_parent_Key.y():
                raise IndexError('The key derived from that index is invalid. Increase the index by 1.')

        public_key_elliptic_point = elliptic_point_from_I_L_int + elliptic_point_from_parent_Key

        child_public_key_coords = (
            public_key_elliptic_point.x().to_bytes(32, byteorder='big'),
            public_key_elliptic_point.y().to_bytes(32, byteorder='big'))

        child_public_key = _bip32_serialize_point(
            P=child_public_key_coords,
            return_compressed=return_compressed)
        
        child_chain_code = I_R

        return child_public_key, child_chain_code