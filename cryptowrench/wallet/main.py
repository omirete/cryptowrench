from __future__ import annotations
from mnemonic import Mnemonic

from .helpers.key_validation import _is_valid_wif
from .helpers.adresses import AddressHandler
from .helpers.derivation_path import derive_wallet, DerivationPath, get_fingerprint
from .helpers.keys import get_private_key_from_wif, get_public_key, get_private_key_and_chain_code_from_seed, ExtendedPrivateKey, get_wif_from_private_key
from .helpers.serialize import _serialize_extended_private_key, _serialize_extended_public_key

class Wallet():

    def __reset_args(self):
        self._prefer_compressed_address = True
        self.words = None
        self.passphrase = ''
        self.seed = None
        self._master_private_key = None
        self._master_chain_code = None


    def __validate_wallet_args(self, mnemonic: str = None, language: str = 'english', strength: int = 128, passphrase: str = '', private_key: bytes = None, chain_code: bytes = None, seed: bytes = None, main_net: bool = True, derivation_path: DerivationPath = None, fingerprint_parent_key: bytes = None, wif: str = None) -> None:
    
        # Type validations -----------------------------------------------------
        if isinstance(mnemonic, str) == False and mnemonic != None:
            raise TypeError("'mnemonic' should be a string of words separated by a space character.")
        if isinstance(passphrase, str) == False and passphrase != None:
            raise TypeError("'passphrase' must be a string.")
        if isinstance(language, str) == False and language != None:
            raise TypeError("'language' should be a string.")
        if isinstance(wif, str) == False and wif != None:
            raise TypeError("'wif' should be a string.")
        if isinstance(seed, bytes) == False and seed != None:
            raise TypeError("'seed' must be provided in bytes.")
        if isinstance(private_key, bytes) == False and private_key != None:
            raise TypeError("'private_key' must be provided in bytes.")
        if isinstance(chain_code, bytes) == False and chain_code != None:
            raise TypeError("'chain_code' must be provided in bytes.")
        if isinstance(fingerprint_parent_key, bytes) == False and fingerprint_parent_key != None:
            raise TypeError("'fingerprint_parent_key' must be provided in bytes.")
        if isinstance(main_net, bool) == False and chain_code != None:
            raise TypeError("'main_net' must be either True or False.")
        if isinstance(derivation_path, DerivationPath) == False and derivation_path != None:
            raise TypeError("'derivation_path' must be a 'DerivationPath' object.")
        if isinstance(strength, int) == False and strength != None:
            raise TypeError("'strength' must be an int.")
        # ----------------------------------------------------------------------

        # Logical validations --------------------------------------------------

        # As defined in BIP39, the entropy must be a multiple of 32 bits, and its size must be between 128 and 256 bits.
        # Therefore the possible values for `strength` are 128, 160, 192, 224 and 256.
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Invalid strength value. Allowed values are [128, 160, 192, 224, 256].")
        
        if chain_code != None and private_key == None:
            raise Exception("If you provide a chain_code for an extended key, you need to provide a private key as well.")
        
        if (mnemonic != None) + (seed != None) + (private_key != None) + (wif != None) > 1:
            raise Exception("You can create a wallet by using one (and only one) of the following methods: with a mnemonic phrase, a seed, a private key/extended private key or a wif. These four methods are mutually exclusive, so please use only one of them.")

        if wif != None and _is_valid_wif(wif) == False:
            raise ValueError("'wif' is invalid.")
        
        if private_key != None and chain_code == None:
            print("You provided a private key without specifying a chain code. You won't be able to generate child wallets (or 'hierarchical deterministic wallets', as they are called).")
        if wif != None:
            print("You provided a wif. Since it only contains information about the private key (but not about the chain code), you won't be able to generate child wallets (or 'hierarchical deterministic wallets', as they are called).")
        # ----------------------------------------------------------------------

    def __init_from_scratch__(self, language: str, strength: int, passphrase: str):
        available_languages = ', '.join(Mnemonic.list_languages())
        assert language in Mnemonic.list_languages(), f'Language not available. Please use one of the following: {available_languages}'
        words = Mnemonic(language).generate(strength)
        self.from_mnemonic(mnemonic=words, passphrase=passphrase)

    def from_seed(self, seed: bytes):
        self.__validate_wallet_args(seed=seed)
        extended_private_key = get_private_key_and_chain_code_from_seed(seed)
        self.__reset_args()
        self.seed = seed
        self._master_private_key = extended_private_key.private_key
        self._master_chain_code  = extended_private_key.chain_code

    def from_mnemonic(self, mnemonic: str, passphrase: str):
        self.__validate_wallet_args(mnemonic=mnemonic, passphrase=passphrase)
        if len(mnemonic.split(' ')) < 12:
            print('You are using less than 12 words to generate your wallet. This is considered unsafe and is not recommended.')
        seed = Mnemonic.to_seed(mnemonic, passphrase)
        self.__reset_args()
        self.words = mnemonic
        self.passphrase = passphrase
        self.from_seed(seed)

    def from_wif(self, wif: str):
        (private_key, main_net, use_with_compressed_public_key) = get_private_key_from_wif(wif)
        self.__reset_args()
        self._master_private_key = private_key
        self.main_net = main_net
        self._prefer_compressed_address = use_with_compressed_public_key

    def from_private_key_and_chain_code(self, private_key: bytes, chain_code: bytes):
        self.__validate_wallet_args(private_key=private_key,chain_code=chain_code)
        self.__reset_args()
        self._master_private_key = private_key
        self._master_chain_code = chain_code

    def __init__(self, mnemonic: str = None, language: str = 'english', strength: int = 128, passphrase: str = '', private_key: bytes = None, chain_code: bytes = None, seed: bytes = None, main_net: bool = True, derivation_path: DerivationPath = None, fingerprint_parent_key: bytes = None, wif: str = None) -> None:
        self.__reset_args()
        self.main_net = main_net
        self.derivation_path = derivation_path
        self.fingerprint_parent_key = fingerprint_parent_key

        self.__validate_wallet_args(
            mnemonic=mnemonic,
            language=language,
            strength=strength,
            passphrase=passphrase,
            private_key=private_key,
            chain_code=chain_code,
            seed=seed,
            main_net=main_net,
            derivation_path=derivation_path,
            fingerprint_parent_key=fingerprint_parent_key)
        
        if mnemonic != None:
            self.from_mnemonic(mnemonic=mnemonic, passphrase=passphrase)
        elif seed != None:
            self.from_seed(seed=seed)
        elif private_key != None:
            self.from_private_key_and_chain_code(private_key=private_key, chain_code=chain_code)
        elif wif != None:
            self.from_wif(wif)
        else:
            self.__init_from_scratch__(
                language=language,
                strength=strength,
                passphrase=passphrase)
        
        self._master_public_key = get_public_key(self._master_private_key, compressed=True)
        self._master_uncompressed_public_key = get_public_key(self._master_private_key, compressed=False)
    
    def hd_wallet(self, path: str, compress_public_keys: bool = True) -> Wallet:
        derivation_path = DerivationPath(path)
        extended_private_key: ExtendedPrivateKey = derive_wallet(
            derivation_path=derivation_path,
            master_private_key=self._master_private_key,
            master_chain_code=self._master_chain_code,
            flag_compress_public_keys=compress_public_keys,
            main_net=self.main_net)
        
        if derivation_path.depth == 0:
            fingerprint_parent_key = bytes.fromhex('00000000')
        else:
            fingerprint_parent_key = get_fingerprint(
                private_key=extended_private_key.parent.private_key
            )
        return Wallet(
            private_key=extended_private_key.private_key,
            chain_code=extended_private_key.chain_code,
            main_net=self.main_net,
            derivation_path=derivation_path,
            fingerprint_parent_key=fingerprint_parent_key)
    
    @property
    def wif(self):
        return get_wif_from_private_key(
            private_key=self._master_private_key,
            main_net=self.main_net,
            generate_compressed=True # CHECK
        )

    @property
    def wif_uncompressed_key(self):
        return get_wif_from_private_key(
            private_key=self._master_private_key,
            main_net=self.main_net,
            generate_compressed=False # CHECK
        )

    @property
    def address(self):
        return AddressHandler(
            public_key=self._master_public_key,
            uncompressed_public_key=self._master_uncompressed_public_key,
            main_net=self.main_net
        )
    
    @property
    def serialized_extended_public_key(self):
        if self.derivation_path != None and self._master_chain_code != None:
            return _serialize_extended_public_key(
                public_key=self._master_public_key,
                chain_code=self._master_chain_code,
                purpose=self.derivation_path.purpose,
                depth=self.derivation_path.depth,
                fingerprint_parent_key=self.fingerprint_parent_key,
                child_number=self.derivation_path.child_number,
                main_net=self.main_net,
            )
        else:
            return b'-'
    
    @property
    def serialized_extended_private_key(self):
        if self.derivation_path != None and self._master_chain_code != None:
            return _serialize_extended_private_key(
                private_key=self._master_private_key,
                chain_code=self._master_chain_code,
                purpose=self.derivation_path.purpose,
                depth=self.derivation_path.depth,
                fingerprint_parent_key=self.fingerprint_parent_key,
                child_number=self.derivation_path.child_number,
                main_net=self.main_net,
            )
        else:
            return b'-'
    
    def print_wallet_info(self):
        lines = []
        if self.seed != None:
            lines.append('Seed:                               ' + self.seed.hex())

        lines.extend([
            'Private key (raw hex):              ' + self._master_private_key.hex(),
            'Private key (serialized):           ' + self.serialized_extended_private_key.decode('utf-8'),
            'Public key (raw hex):               ' + self._master_public_key.hex(),
            'Public key (serialized):            ' + self.serialized_extended_public_key.decode('utf-8'),
            'Uncompressed pub. key (raw hex):    ' + self._master_uncompressed_public_key.hex(),
            'Uncompressed pub. key (serialized): ' + self._master_public_key.hex(),
            'WIF:                                ' + self.wif,
            'WIF (uncompressed key):             ' + self.wif_uncompressed_key,
            'Address (P2PKH):                    ' + self.address.bitcoin.P2PKH,
            'Address (P2PKH, uncompressed key):  ' + self.address.bitcoin.P2PKH_uncompressed,
            'Address (P2SH):                     ' + self.address.bitcoin.P2SH,
            'Address (P2SH, uncompressed key):   ' + self.address.bitcoin.P2SH_uncompressed,
            'Address (Bech32):                   ' + self.address.bitcoin.P2WPKH_wit0,
        ])
        print('\n'.join(lines))
