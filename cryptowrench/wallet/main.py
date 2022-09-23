from __future__ import annotations
from mnemonic import Mnemonic

from .helpers.adresses import AddressHandler
from .helpers.derivation_path import derive_wallet, DerivationPath, get_fingerprint
from .helpers.keys import get_public_key, get_private_key_and_chain_code_from_seed, ExtendedPrivateKey, get_wif_from_private_key
from .helpers.serialize import _serialize_extended_private_key, _serialize_extended_public_key


class Wallet():
    def __init__(self, mnemonic: str = None, language: str = 'english', strength: int = 128, passphrase: str = '', private_key: bytes = None, chain_code: bytes = None, seed: bytes = None, main_net: bool = True, derivation_path: DerivationPath = None, fingerprint_parent_key: bytes = None) -> None:
        self.main_net = main_net
        self.derivation_path = derivation_path
        self.fingerprint_parent_key = fingerprint_parent_key
        if private_key == None and chain_code != None:
            raise Exception("If you provide a chain_code for an extended key, you need to provide a private key as well.")
        if (mnemonic != None) + (seed != None) + (private_key != None) > 1:
            raise Exception("The mnemonic, the seed and the private key/chain code are mutually exclusive. Please provide at most one of them.")
        if private_key != None and chain_code == None:
            print("You provided a private key without specifying a chain code. You won't be able to generate a hierarchical deterministic wallet.")
        if private_key != None:
            self._master_private_key = private_key
            self._master_chain_code = chain_code
            self.words = None
            self.seed = None
        else:
            if seed != None:
                self.seed = seed
            elif mnemonic != None:
                if len(mnemonic.split(' ')) < 12:
                    print('You are using less than 12 words to generate your wallet. This is considered unsafe and is not recommended.')
                self.words = mnemonic
                self.seed = Mnemonic.to_seed(self.words, passphrase)
            else:
                # Both the private key and the mnemonic are empty, so let's create
                # a seed based on a random mnemonic and use that to create the keys.
                available_languages = ', '.join(Mnemonic.list_languages())
                assert language in Mnemonic.list_languages(), f'Language not available. Please use one of the following: {available_languages}'
                self.words = Mnemonic(language).generate(strength)
                self.seed = Mnemonic.to_seed(self.words, passphrase)
            
        if self.seed != None:
            extended_private_key = get_private_key_and_chain_code_from_seed(self.seed)
            self._master_private_key = extended_private_key.private_key
            self._master_chain_code  = extended_private_key.chain_code
        
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
    def address(self):
        return AddressHandler(
            public_key=self._master_public_key,
            uncompressed_public_key=self._master_uncompressed_public_key,
            main_net=self.main_net
        )
    
    @property
    def serialized_extended_public_key(self):
        return _serialize_extended_public_key(
            public_key=self._master_public_key,
            chain_code=self._master_chain_code,
            purpose=self.derivation_path.purpose,
            depth=self.derivation_path.depth,
            fingerprint_parent_key=self.fingerprint_parent_key,
            child_number=self.derivation_path.child_number,
            main_net=self.main_net,
        )
    
    @property
    def serialized_extended_private_key(self):
        return _serialize_extended_private_key(
            private_key=self._master_private_key,
            chain_code=self._master_chain_code,
            purpose=self.derivation_path.purpose,
            depth=self.derivation_path.depth,
            fingerprint_parent_key=self.fingerprint_parent_key,
            child_number=self.derivation_path.child_number,
            main_net=self.main_net,
        )
    