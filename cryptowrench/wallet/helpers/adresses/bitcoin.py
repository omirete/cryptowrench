import hashlib, bech32
from base58 import b58encode, BITCOIN_ALPHABET

from ..hashfuncs import get_hash160
from ..key_validation import _is_valid_public_key, _is_public_key_compressed

class BitcoinAddressHandler():
    def __init__(self, public_key: bytes, uncompressed_public_key: bytes, main_net: bool) -> None:
        self._public_key = public_key
        self._uncompressed_public_key = uncompressed_public_key
        self._main_net = main_net

    @property
    def P2PKH(self):
        return address_P2PKH(
            public_key=self._public_key,
            main_net=self._main_net
        )
    
    @property
    def P2PKH_uncompressed(self):
        return address_P2PKH(
            public_key=self._uncompressed_public_key,
            main_net=self._main_net
        )
    
    @property
    def P2SH(self):
        return address_P2SH(
            public_key=self._public_key,
            main_net=self._main_net)
    
    @property
    def P2SH_uncompressed(self):
        return address_P2SH(
            public_key=self._uncompressed_public_key,
            main_net=self._main_net)
        
    @property
    def P2WPKH_wit0(self):
        return get_P2WPKH_address(
            compressed_public_key=self._public_key,
            witness_version=0,
            main_net=self._main_net
        )

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

        return str(b58encode(address_before_b58_encoding, alphabet=BITCOIN_ALPHABET), encoding='utf-8')

def address_P2SH(public_key: bytes, main_net: bool = True):

    assert _is_valid_public_key(public_key) == True, 'Invalid public key.'
    assert isinstance(main_net, bool) == True, 'The argument \'main_net\' has to be either True or False.'

    # Pay-to-Script-Hash
    # https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    # Not implemented yet.

    # var sha_result_1 = SHA256(key_bytes);
    # var keyhash = RIPEMD160(sha_result_1);
    # var redeemscript = [0x00, 0x14];
    # redeemscript.push.apply(redeemscript, keyhash);
    # var redeemscripthash = [isTestnet ? 0xC4 : 0x05];
    # redeemscripthash.push.apply(redeemscripthash, RIPEMD160(SHA256(redeemscript)));
    # redeemscripthash.push.apply(redeemscripthash, SHA256(SHA256(redeemscripthash)).slice(0, 4));
    # return base58encode(redeemscripthash);
    
    MAIN_NET = bytes.fromhex('05')
    TEST_NET = bytes.fromhex('C4')

    # OPCODES
    OP_0 = bytes.fromhex('00')
    # The opcode in the following line indicates the amount of bytes that are
    # considered to be data and that should be pushed onto the stack.
    NA_20 = bytes.fromhex('14') # 20 in dec is 14 in hex
    
    script_to_hash = OP_0 + NA_20 + get_hash160(public_key) # hash160 results in
                                                            # 20 bytes of data.
    hashed_script = get_hash160(script_to_hash)

    version = MAIN_NET if main_net == True else TEST_NET

    checksum = hashlib.sha256(version + hashed_script).digest()
    checksum = hashlib.sha256(checksum).digest()
    checksum = checksum[:4]

    return str(b58encode(version + hashed_script + checksum), encoding='utf-8')

def get_P2WPKH_address(compressed_public_key, witness_version, main_net=True):

    # See BIP 84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
    # Title: Derivation scheme for P2WPKH based accounts
    
    assert _is_public_key_compressed(compressed_public_key), 'Public key must be in compressed form for this type of address.'
    assert _is_valid_public_key(compressed_public_key) == True, 'Invalid public key.'
    assert isinstance(main_net, bool) == True, 'The argument \'main_net\' has to be either True or False.'

    # To understand why the public key must be in compressed form, see BIP-0143:
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#restrictions-on-public-key-type

    # Addresses format as described in BIP-0173:
    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    
    # Reminder to understand how is hash160 defined:
    # hash160(x) = f(x) = ripemd160(sha256(x))
    hash160_as_bytes = get_hash160(compressed_public_key)
    
    hrp = 'bc' if main_net == True else 'tb'

    return bech32.encode(
        hrp=hrp,
        witver=witness_version,
        witprog=hash160_as_bytes)