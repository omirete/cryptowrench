import hashlib
from base58 import b58encode

from ..hashfuncs import get_hash160

def address_P2PKH(public_key: bytes, main_net: bool = True):
        # assert _is_valid_public_key(public_key) == True, 'Invalid public key.'
        assert isinstance(main_net, bool) == True, 'The argument \'main_net\' has to be either True or False.'

        # Pay-to-PubkeyHash
        # Not implemented yet.
        MAIN_NET = bytes.fromhex('00')
        TEST_NET = bytes.fromhex('6F')
        
        hash_160 = get_hash160(public_key) # ripemd160(sha256(value))

        version = MAIN_NET if main_net == True else TEST_NET

        version_and_hash160 = version + hash_160

        checksum = hashlib.sha256(version_and_hash160).digest()
        checksum = hashlib.sha256(checksum).digest()
        checksum = checksum[:4]

        address_before_b58_encoding = version_and_hash160 + checksum

        return str(b58encode(address_before_b58_encoding), encoding='utf-8')

