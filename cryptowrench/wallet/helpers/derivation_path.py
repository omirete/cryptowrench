import hashlib, hmac
from typing import Union

from .elliptic_math import SECP256K1_Helpers, _bip32_point, _bip32_serialize_point
from .key_validation import _is_valid_chain_code, _is_valid_private_key
from .keys import get_public_key, ExtendedPrivateKey
from .hashfuncs import get_hash160

class DerivationPath():
    def __init__(self, path: str) -> None:
        assert path != '', "Please enter a path to derive a wallet."
        assert isinstance(path, str), "The path should be a string. Example: m/44'/0'/0'/0/0"
        path = path.replace(' ', '')
        str_digits = [str(d) for d in range(10)]
        for c in path:
            assert ['m', '/', "'", *str_digits].count(c.lower()) > 0, f"Invalid character detected in path: {c}"
        assert path.count('/') < 6, "A derivation path can have at most 5 elements, as in this example: m/44'/0'/0'/0/0"
        path_parts = path.split('/')
        assert len(path_parts) > 0, "Could not parse the derivation path. Make sure it has the correct format. Example: m/44'/0'/0'/0/0"

        self.key_type = None
        self.purpose = None
        self.coin_type = None
        self.account = None
        self.change = None
        self.address_index = None

        try:
            # We try to fill in order all of the values that we can.
            # When we reach an index that does not exist in path_parts, it will
            # catch the IndexError and the code will carry on. With the values
            # that were found up to that point. (The rest of the parts will be 
            # 'None' because the are not present in the provided derivation
            # path).
            self.key_type = path_parts[0]
            self.purpose = path_parts[1]
            self.coin_type = path_parts[2]
            self.account = path_parts[3]
            self.change = path_parts[4]
            # See spec in: 
            # https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#Change)
            # Strictly speaking (according to the spec cited above) the "change"
            # component can only be 0 or 1. We however leave this restriction
            # away, because one of the test vectors in BIP32 asks us to test the
            # path m/0'/1/2'/2, where the change is set to 2. (see:
            # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors).
            # Because of this, the following line is commented out but left
            # there anyway for future reference.
            # assert self.change == None or ['0', '1'].count(str(self.change)) == 1, 'Only 0 or 1 can be used for the "change" part of the wallet\'s derivation path.'
            self.address_index = path_parts[5]
        except IndexError:
            pass

        try:
            pass
        except:
            pass
    
    @property
    def depth(self):
        derivation_index_secuence = (
            self.purpose,
            self.coin_type,
            self.account,
            self.change,
            self.address_index
        )
        depth = 0
        for next_index in derivation_index_secuence:
            if next_index == None:
                break
            else:
                depth += 1
        return depth
    
    @property
    def child_number(self):
        derivation_index_secuence = (
            self.purpose,
            self.coin_type,
            self.account,
            self.change,
            self.address_index
        )
        index = 0
        for next_index in derivation_index_secuence:
            if next_index == None:
                break
            else:
                index = next_index
        return index
        



def get_fingerprint(private_key: bytes = None) -> bytes:
    if private_key == None:
        return bytes.fromhex('00000000')
    else:
        public_key_compressed = get_public_key(
            private_key=private_key,
            compressed=True) # Must be compressed (serialized), as per BIP32.
        return get_hash160(public_key_compressed)[:4] # Fingerprint

def derive_wallet(derivation_path: DerivationPath, master_private_key: bytes, master_chain_code: bytes, flag_compress_public_keys: bool = True, main_net: bool = True):
    
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
    assert derivation_path.key_type == 'm', f"Unsuported key type: {derivation_path.key_type}. Please use 'm'."
    
    purpose = derivation_path.purpose
    coin_type = derivation_path.coin_type
    account = derivation_path.account
    change = derivation_path.change
    address_index = derivation_path.address_index

    coin_type = _derivation_path_component_to_int(coin_type)
    account = _derivation_path_component_to_int(account)
    # See spec in: 
    # https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#Change)
    # Strictly speaking (according to the spec cited above) the "change"
    # component can only be 0 or 1. We however leave this restriction
    # away, because one of the test vectors in BIP32 asks us to test the
    # path m/0'/1/2'/2, where the change is set to 2. (see:
    # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors).
    # Because of this, the "change" component is teated as any other, as seen in
    # the following line.
    change = _derivation_path_component_to_int(change)
    address_index = _derivation_path_component_to_int(address_index)
    
    current_key = master_private_key # This is the starting key at depth 0.
    current_chain_code = master_chain_code
    index = 0

    # Path scheme: m / purpose' / coin_type' / account' / change / address_index
    
    derivation_index_secuence = (purpose, coin_type, account, change, address_index)
    depth = 0

    last_key = current_key
    last_chain_code = current_chain_code

    for next_index in derivation_index_secuence:
        if next_index == None:
            break
        else:
            depth += 1
            last_key = current_key
            last_chain_code = current_chain_code
            index = next_index
            current_key, current_chain_code = ChildKeyDerivation_private(
                last_key,
                parent_chain_code_as_bytes=last_chain_code,
                i=index)
    
    return ExtendedPrivateKey(
        private_key=current_key,
        chain_code=current_chain_code,
        parent=ExtendedPrivateKey(
            private_key=last_key if depth > 0 else bytes.fromhex('00000000'),
            chain_code=last_chain_code
            # chain_code=last_chain_code if depth > 0 else bytes.fromhex('00000000')
        ))

def ChildKeyDerivation_private(parent_private_key_as_bytes, parent_chain_code_as_bytes, i):
    
    assert _is_valid_private_key(parent_private_key_as_bytes) == True, 'Invalid private key.'
    assert _is_valid_chain_code(parent_chain_code_as_bytes) == True, 'Invalid chain code.'
    i = _derivation_path_component_to_int(i)
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
    n = SECP256K1_Helpers.order
    
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

def _derivation_path_component_to_int(component: Union[str, int, None]):
    if isinstance(component, str) == True:
        if component[-1] == '\'':
            return 2**31 + int(component[:-1])
        return int(component)
    elif isinstance(component, int):
        return component
    elif component == None:
        return None
    raise Exception(f'Could not parse derivation path component: {component}.')