from __future__ import annotations
from typing import Union, Optional
from mnemonic import Mnemonic
from mnemonic.mnemonic import ConfigurationError

from .helpers.key_validation import _is_valid_private_key, _is_valid_wif
from .helpers.adresses import AddressHandler
from .helpers.derivation_path import derive_wallet, DerivationPath, get_fingerprint
from .helpers.keys import get_private_key_from_wif, get_public_key, get_private_key_and_chain_code_from_seed, ExtendedPrivateKey, get_wif_from_private_key
from .helpers.serialize import _serialize_extended_private_key, _serialize_extended_public_key


class Wallet():

    def __reset_args(self):
        self._prefer_compressed_address = True
        self._words = None
        self._passphrase = ''
        self._seed = None
        self.__set_private_key(None)
        self._master_chain_code = None

    @staticmethod
    def __validate_argument_types(*, required=(), **arguments):
        """Check supplied types; direct imports name the arguments that cannot be None."""
        argument_types = {
            'entropy': bytes,
            'mnemonic': str,
            'seed': bytes,
            'private_key': bytes,
            'wif': str,
            'chain_code': bytes,
            'strength': int,
            'derivation_path': DerivationPath,
            'fingerprint_parent_key': bytes,
            'language': str,
            'passphrase': str,
            'main_net': bool,
        }
        for name, value in arguments.items():
            if value is None and name not in required:
                continue
            expected = argument_types[name]
            if not isinstance(value, expected) or (name == 'strength' and isinstance(value, bool)):
                raise TypeError(f"'{name}' must be {expected.__name__}.")

    @staticmethod
    def __validate_argument_values(**arguments):
        """Check individual values only, without mode rules, notices or state changes."""
        # As defined in BIP39, the entropy must be a multiple of 32 bits (4
        # bytes), and its size must be between 128 and 256 bits (16 and 32
        # bytes).
        entropy = arguments.get('entropy')
        if entropy is not None and len(entropy) not in (16, 20, 24, 28, 32):
            raise ValueError("'entropy' must contain 16, 20, 24, 28 or 32 bytes.")
        # Because of the restrictions on entropy, the possible values for
        # `strength` are 128, 160, 192, 224 and 256 bits.
        strength = arguments.get('strength')
        if strength is not None and strength not in (128, 160, 192, 224, 256):
            raise ValueError('Invalid strength value. Allowed values are [128, 160, 192, 224, 256].')
        language = arguments.get('language')
        if language is not None and language not in Mnemonic.list_languages():
            raise ValueError('Unsupported mnemonic language: ' + language)
        fingerprint = arguments.get('fingerprint_parent_key')
        if fingerprint is not None and len(fingerprint) != 4:
            raise ValueError("'fingerprint_parent_key' must contain exactly four bytes.")
        private_key = arguments.get('private_key')
        if private_key is not None and not _is_valid_private_key(private_key):
            raise ValueError("'private_key' must contain 32 bytes encoding a scalar from 1 up to, but excluding, the secp256k1 order.")
        wif = arguments.get('wif')
        if wif is not None and not _is_valid_wif(wif):
            raise ValueError("'wif' is invalid.")
        mnemonic = arguments.get('mnemonic')
        if mnemonic is not None:
            # Entropy-generated words must use their selected wordlist.
            # Imported words have no language argument, so detect their
            # language instead.
            if language is None:
                try:
                    language = Mnemonic.detect_language(mnemonic)
                except ConfigurationError as error:
                    raise ValueError('Chosen mnemonic is invalid.') from error
            if not Mnemonic(language).check(mnemonic):
                raise ValueError('Chosen mnemonic is invalid.')

    def __init_from_scratch__(self, language: str, strength: int, passphrase: str):
        self.__validate_argument_values(language=language, strength=strength)
        words = Mnemonic(language).generate(strength)
        self.__from_validated_mnemonic(words, passphrase)

    def from_seed(self, seed: bytes):
        self.__validate_argument_types(required=('seed',), seed=seed)
        self.__validate_argument_values(seed=seed)
        extended_private_key = get_private_key_and_chain_code_from_seed(seed)
        self.__validate_argument_values(private_key=extended_private_key.private_key)
        self.__reset_args()
        self._seed = seed
        self.__set_private_key(extended_private_key.private_key)
        self._master_chain_code  = extended_private_key.chain_code

    def from_mnemonic(self, mnemonic: str, passphrase: str = ''):
        self.__validate_argument_types(
            required=('mnemonic', 'passphrase'), mnemonic=mnemonic, passphrase=passphrase)
        self.__validate_argument_values(mnemonic=mnemonic)
        # Split on Unicode whitespace, including the ideographic space used
        # between Japanese mnemonic words; split(' ') only handles ASCII spaces.
        if len(mnemonic.split()) < 12:
            print('You are using less than 12 words to generate your wallet. This is considered unsafe and is not recommended.')
        self.__from_validated_mnemonic(mnemonic, passphrase)

    def __from_validated_mnemonic(self, mnemonic: str, passphrase: str):
        seed = Mnemonic.to_seed(mnemonic, passphrase)
        extended_private_key = get_private_key_and_chain_code_from_seed(seed)
        self.__validate_argument_values(private_key=extended_private_key.private_key)
        self.__reset_args()
        self._words = mnemonic
        self._passphrase = passphrase
        self._seed = seed
        self.__set_private_key(extended_private_key.private_key)
        self._master_chain_code  = extended_private_key.chain_code

    def from_entropy(self, entropy: bytes, passphrase: str = '', language: str = 'english'):
        """Replace this wallet from 128-256 bits of raw BIP39 entropy bytes.

        Entropy must contain 16, 20, 24, 28 or 32 bytes. The optional
        passphrase is used in seed derivation.
        """
        self.__validate_argument_types(
            required=('entropy', 'passphrase', 'language'),
            entropy=entropy, passphrase=passphrase, language=language)
        self.__validate_argument_values(entropy=entropy, language=language)
        mnemo = Mnemonic(language)
        words = mnemo.to_mnemonic(entropy)
        self.__validate_argument_values(mnemonic=words, language=language)
        self.__from_validated_mnemonic(words, passphrase)

    def from_wif(self, wif: str):
        self.__validate_argument_types(required=('wif',), wif=wif)
        self.__validate_argument_values(wif=wif)
        (private_key, use_with_compressed_public_key, main_net) = get_private_key_from_wif(wif)
        self.__validate_argument_values(private_key=private_key)
        print("You provided a wif. Since it only contains information about the private key (but not about the chain code), you won't be able to generate child wallets (or 'hierarchical deterministic wallets', as they are called).")
        self.__reset_args()
        self.__set_private_key(private_key)
        self._main_net = main_net
        self._prefer_compressed_address = use_with_compressed_public_key

    def from_extended_private_key(self, private_key: bytes, chain_code: bytes):
        self.__validate_argument_types(
            required=('private_key', 'chain_code'), private_key=private_key, chain_code=chain_code)
        self.__validate_argument_values(private_key=private_key, chain_code=chain_code)
        self.__reset_args()
        self.__set_private_key(private_key)
        self._master_chain_code = chain_code
    
    def from_private_key(self, private_key: bytes):
        self.__validate_argument_types(required=('private_key',), private_key=private_key)
        self.__validate_argument_values(private_key=private_key)
        print("You provided a private key without specifying a chain code. You won't be able to generate child wallets (or 'hierarchical deterministic wallets', as they are called).")
        self.__reset_args()
        self.__set_private_key(private_key)

    @staticmethod
    def __determine_initialization_mode(**sources):
        """Select one supplied source, or random generation when all are None."""
        supplied = [name for name, value in sources.items() if value is not None]
        if len(supplied) > 1:
            raise ValueError('Wallet sources are mutually exclusive: ' + ', '.join(supplied))
        return supplied[0] if supplied else 'random'

    @staticmethod
    def __reject_unsupported_options(mode, allowed, **options):
        for name, value in options.items():
            if value is not None and name not in allowed:
                raise ValueError(f"'{mode}' and '{name}' cannot be supplied together.")

    def __validate_random_options(self, **options):
        self.__reject_unsupported_options(
            'random', {'strength', 'language', 'passphrase', 'main_net'}, **options)

    def __validate_entropy_options(self, **options):
        self.__reject_unsupported_options(
            'entropy', {'language', 'passphrase', 'main_net'}, **options)

    def __validate_mnemonic_options(self, **options):
        self.__reject_unsupported_options('mnemonic', {'passphrase', 'main_net'}, **options)

    def __validate_seed_options(self, **options):
        self.__reject_unsupported_options('seed', {'main_net'}, **options)

    def __validate_private_key_options(self, **options):
        self.__reject_unsupported_options(
            'private_key', {'chain_code', 'main_net', 'derivation_path', 'fingerprint_parent_key'}, **options)
        path = options['derivation_path']
        fingerprint = options['fingerprint_parent_key']
        if path is not None or fingerprint is not None:
            if options['chain_code'] is None:
                raise ValueError("'derivation_path' and 'fingerprint_parent_key' require 'chain_code'.")
            if path is None or fingerprint is None:
                raise ValueError("'derivation_path' and 'fingerprint_parent_key' must be supplied together.")

    def __validate_wif_options(self, **options):
        self.__reject_unsupported_options('wif', set(), **options)

    def __validate_initialization_options(self, mode, **options):
        """Dispatch combination checks; each mode owns its compatibility rules."""
        validators = {
            'random': self.__validate_random_options,
            'entropy': self.__validate_entropy_options,
            'mnemonic': self.__validate_mnemonic_options,
            'seed': self.__validate_seed_options,
            'private_key': self.__validate_private_key_options,
            'wif': self.__validate_wif_options,
        }
        validators[mode](**options)

    def __init__(self, mnemonic: str = None, language: Optional[str] = None, strength: Optional[int] = None, passphrase: Optional[str] = None, private_key: bytes = None, chain_code: bytes = None, seed: bytes = None, main_net: Optional[bool] = None, derivation_path: DerivationPath = None, fingerprint_parent_key: bytes = None, wif: str = None, entropy: Optional[bytes] = None) -> None:
        arguments = dict(
            entropy=entropy,
            mnemonic=mnemonic,
            seed=seed,
            private_key=private_key,
            wif=wif,
            chain_code=chain_code,
            strength=strength,
            language=language,
            passphrase=passphrase,
            main_net=main_net,
            derivation_path=derivation_path,
            fingerprint_parent_key=fingerprint_parent_key)
        self.__validate_argument_types(**arguments)
        mode = self.__determine_initialization_mode(
            entropy=entropy,
            mnemonic=mnemonic,
            seed=seed,
            private_key=private_key,
            wif=wif)
        self.__validate_initialization_options(
            mode,
            strength=strength,
            language=language,
            passphrase=passphrase,
            main_net=main_net,
            chain_code=chain_code,
            derivation_path=derivation_path,
            fingerprint_parent_key=fingerprint_parent_key)

        language = 'english' if language is None else language
        passphrase = '' if passphrase is None else passphrase
        main_net = True if main_net is None else main_net
        # Keep imported mnemonic validation free of a resolved generation language.
        self.__validate_argument_values(**arguments)

        self.__reset_args()
        self._main_net = main_net
        self._derivation_path = derivation_path
        self._fingerprint_parent_key = fingerprint_parent_key
        
        if mode == 'mnemonic':
            self.from_mnemonic(mnemonic=mnemonic, passphrase=passphrase)
        elif mode == 'entropy':
            self.from_entropy(entropy, passphrase=passphrase, language=language)
        elif mode == 'seed':
            self.from_seed(seed=seed)
        elif mode == 'private_key':
            if chain_code is None:
                self.from_private_key(private_key)
            else:
                self.from_extended_private_key(private_key=private_key, chain_code=chain_code)
        elif mode == 'wif':
            self.from_wif(wif)
        else:
            self.__init_from_scratch__(
                language=language,
                # None means no strength was supplied; random generation defaults to 128 bits.
                strength=128 if strength is None else strength,
                passphrase=passphrase)
    
    def hd_wallet(self, path: str, compress_public_keys: bool = True) -> Wallet:
        assert self.chain_code != None, 'You have not specified a chain code for your wallet. Together with the private key, the chain code completes the "extended private key" and is needed for the generation of child wallets.'
        derivation_path = DerivationPath(path)
        extended_private_key: ExtendedPrivateKey = derive_wallet(
            derivation_path=derivation_path,
            master_private_key=self.private_key,
            master_chain_code=self.chain_code,
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
    def private_key(self) -> bytes:
        return self._master_private_key
    
    def __set_private_key(self, new_val: bytes):
        self._master_private_key = new_val
        if new_val != None:
            self._master_public_key = get_public_key(new_val, compressed=True)
            self._master_uncompressed_public_key = get_public_key(new_val, compressed=False)
        else:
            self._master_public_key = None
            self._master_uncompressed_public_key = None
    
    @property
    def chain_code(self) -> Union[bytes, None]:
        return self._master_chain_code
    
    @property
    def seed(self) -> Union[bytes, None]:
        return self._seed
    
    @property
    def words(self) -> Union[str, None]:
        return self._words
    
    @property
    def passphrase(self) -> str:
        return self._passphrase

    @property
    def public_key(self) -> bytes:
        return self._master_public_key
    
    @property
    def public_key_uncompressed(self) -> bytes:
        return self._master_uncompressed_public_key

    @property
    def wif(self) -> str:
        return get_wif_from_private_key(
            private_key=self.private_key,
            main_net=self.main_net,
            generate_compressed=True # CHECK
        )

    @property
    def wif_uncompressed_key(self) -> str:
        return get_wif_from_private_key(
            private_key=self.private_key,
            main_net=self.main_net,
            generate_compressed=False # CHECK
        )

    @property
    def address(self):
        return AddressHandler(
            public_key=self.public_key,
            uncompressed_public_key=self.public_key_uncompressed,
            main_net=self.main_net
        )
    
    @property
    def derivation_path(self):
        return self._derivation_path

    @property
    def serialized_extended_public_key(self):
        if self.derivation_path != None and self.chain_code != None:
            return _serialize_extended_public_key(
                public_key=self.public_key,
                chain_code=self.chain_code,
                purpose=self.derivation_path.purpose,
                depth=self.derivation_path.depth,
                fingerprint_parent_key=self._fingerprint_parent_key,
                child_number=self.derivation_path.child_number,
                main_net=self.main_net,
            )
        else:
            return b'-'
    
    @property
    def serialized_extended_private_key(self):
        if self.derivation_path != None and self.chain_code != None:
            return _serialize_extended_private_key(
                private_key=self.private_key,
                chain_code=self.chain_code,
                purpose=self.derivation_path.purpose,
                depth=self.derivation_path.depth,
                fingerprint_parent_key=self._fingerprint_parent_key,
                child_number=self.derivation_path.child_number,
                main_net=self.main_net,
            )
        else:
            return b'-'
    
    @property
    def main_net(self) -> bool:
        return self._main_net

    @property
    def test_net(self) -> bool:
        return not self._main_net
    
    def print_wallet_info(self):
        lines = [
            'Seed:                               ' + self.seed.hex() if self.seed != None else '-',
            'Private key (raw hex):              ' + self.private_key.hex(),
            'Private key (serialized):           ' + self.serialized_extended_private_key.decode('utf-8'),
            'Public key (raw hex):               ' + self.public_key.hex(),
            'Public key (serialized):            ' + self.serialized_extended_public_key.decode('utf-8'),
            'Uncompressed pub. key (raw hex):    ' + self.public_key_uncompressed.hex(),
            # 'Uncompressed pub. key (serialized): ' + ,
            'WIF:                                ' + self.wif,
            'WIF (uncompressed key):             ' + self.wif_uncompressed_key,
            'Address (P2PKH):                    ' + self.address.bitcoin.P2PKH,
            'Address (P2PKH, uncompressed key):  ' + self.address.bitcoin.P2PKH_uncompressed,
            'Address (P2SH):                     ' + self.address.bitcoin.P2SH,
            'Address (P2SH, uncompressed key):   ' + self.address.bitcoin.P2SH_uncompressed,
            'Address (Bech32):                   ' + self.address.bitcoin.P2WPKH_wit0,
        ]
        print('\n'.join(lines))
