"""Constructor compatibility and imported-wallet regression checks."""

import contextlib
import io
import unittest
from unittest.mock import patch

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.derivation_path import DerivationPath
from cryptowrench.wallet.helpers.keys import get_wif_from_private_key


class WalletArgumentTests(unittest.TestCase):
    def setUp(self):
        self.root = Wallet(entropy=bytes(16))
        self.sources = {
            'random': {}, 'entropy': {'entropy': bytes(16)},
            'mnemonic': {'mnemonic': self.root.words}, 'seed': {'seed': self.root.seed},
            'private_key': {'private_key': self.root.private_key}, 'wif': {'wif': self.root.wif},
        }

    def create(self, **kwargs):
        # Existing private-key/WIF import notices are not relevant to assertions.
        with contextlib.redirect_stdout(io.StringIO()):
            return Wallet(**kwargs)

    def test_creation_mode_option_matrix(self):
        allowed = {
            'random': {'strength', 'language', 'passphrase', 'main_net'},
            'entropy': {'language', 'passphrase', 'main_net'},
            'mnemonic': {'passphrase', 'main_net'},
            'seed': {'main_net'}, 'private_key': {'chain_code', 'main_net'}, 'wif': set(),
        }
        options = {
            'strength': (128, 256), 'language': ('english', 'japanese'),
            'passphrase': ('', 'secret'), 'main_net': (True, False),
            'chain_code': (bytes(32), self.root.chain_code),
        }
        for mode, source in self.sources.items():
            for option, values in options.items():
                for value in values:
                    with self.subTest(mode=mode, option=option, value=value):
                        if option in allowed[mode]:
                            self.create(**source, **{option: value})
                        else:
                            with self.assertRaises(ValueError) as raised:
                                self.create(**source, **{option: value})
                            self.assertIn(option, str(raised.exception))
                            self.assertIn(mode, str(raised.exception))

    def test_every_source_pair_is_rejected(self):
        sources = list(self.sources.items())[1:]
        for index, (first, first_args) in enumerate(sources):
            for second, second_args in sources[index + 1:]:
                with self.subTest(first=first, second=second):
                    with self.assertRaises(ValueError) as raised:
                        self.create(**first_args, **second_args)
                    self.assertIn(first, str(raised.exception))
                    self.assertIn(second, str(raised.exception))

    def test_none_means_absent_for_optional_arguments(self):
        absent = dict(entropy=None, mnemonic=None, seed=None, private_key=None, wif=None,
                      chain_code=None, strength=None, derivation_path=None, fingerprint_parent_key=None,
                      language=None, passphrase=None, main_net=None)
        for mode, source in self.sources.items():
            with self.subTest(mode=mode):
                with patch('mnemonic.mnemonic.os.urandom', side_effect=lambda count: bytes(count)):
                    omitted = self.create(**source)
                    explicit_none = self.create(**{**absent, **source})
                self.assertEqual(explicit_none.__dict__, omitted.__dict__)

    def test_invalid_types(self):
        for option, value in dict(entropy='00' * 16, mnemonic=123, seed='seed',
                                  private_key='key', wif=b'wif', chain_code='code',
                                  strength=True, language=123, passphrase=b'password',
                                  main_net=1, derivation_path='m', fingerprint_parent_key='0000').items():
            with self.subTest(option=option):
                with self.assertRaises(TypeError):
                    self.create(**{option: value})

    def test_metadata_requires_extended_private_key_and_both_fields(self):
        path = DerivationPath('m')
        metadata = {'derivation_path': path, 'fingerprint_parent_key': bytes(4)}
        for mode, source in self.sources.items():
            for supplied in (metadata, {'derivation_path': path}, {'fingerprint_parent_key': bytes(4)}):
                with self.subTest(mode=mode, supplied=supplied):
                    with self.assertRaises(ValueError):
                        self.create(**source, **supplied)
        extended = {'private_key': self.root.private_key, 'chain_code': self.root.chain_code}
        for supplied in ({'derivation_path': path}, {'fingerprint_parent_key': bytes(4)}):
            with self.assertRaisesRegex(ValueError, 'together'):
                self.create(**extended, **supplied)
        for size in (0, 3, 5):
            with self.subTest(fingerprint_size=size):
                with self.assertRaisesRegex(ValueError, 'four bytes'):
                    self.create(**extended, derivation_path=path, fingerprint_parent_key=bytes(size))
        imported = self.create(**extended, **metadata)
        self.assertEqual(imported.serialized_extended_private_key, self.root.hd_wallet('m').serialized_extended_private_key)
        child = self.root.hd_wallet("m/84'/0'/0'/0/0")
        self.assertEqual(child.derivation_path.depth, 5)
        self.assertTrue(child.serialized_extended_public_key.startswith(b'zpub'))

    def test_accepted_options_affect_results(self):
        # Deterministic randomness lets us isolate strength, language and passphrase.
        with patch('mnemonic.mnemonic.os.urandom', side_effect=lambda count: bytes(count)):
            default = self.create()
            self.assertEqual(default.seed, self.root.seed)
            self.assertEqual(default.passphrase, '')
            self.assertTrue(default.main_net)
            self.assertEqual(len(self.create(strength=256).words.split()), 24)
            for mode in ('random', 'entropy'):
                self.assertNotEqual(self.create(**self.sources[mode], language='japanese').words, default.words)
            for mode in ('random', 'entropy', 'mnemonic'):
                protected = self.create(**self.sources[mode], passphrase='secret')
                self.assertNotEqual(protected.seed, default.seed)
                self.assertEqual(protected.passphrase, 'secret')
            for mode in ('random', 'entropy', 'mnemonic', 'seed', 'private_key'):
                main = self.create(**self.sources[mode], main_net=True)
                test = self.create(**self.sources[mode], main_net=False)
                self.assertEqual(main.private_key, test.private_key)
                self.assertNotEqual(main.address.bitcoin.P2PKH, test.address.bitcoin.P2PKH)
        extended = self.create(private_key=self.root.private_key, chain_code=self.root.chain_code)
        self.assertEqual(extended.chain_code, self.root.chain_code)
        self.assertEqual(extended.hd_wallet('m').private_key, self.root.private_key)

    def test_wif_network_and_compression_and_failed_import(self):
        for main_net in (True, False):
            for compressed in (True, False):
                with self.subTest(main_net=main_net, compressed=compressed):
                    wif = get_wif_from_private_key(self.root.private_key, main_net, compressed)
                    for entrypoint in ('constructor', 'method'):
                        wallet = self.create(wif=wif) if entrypoint == 'constructor' else self.create()
                        if entrypoint == 'method':
                            with contextlib.redirect_stdout(io.StringIO()):
                                wallet.from_wif(wif)
                        self.assertEqual(wallet.private_key, self.root.private_key)
                        self.assertEqual(wallet.main_net, main_net)
                        self.assertEqual(wallet._prefer_compressed_address, compressed)
                        before = wallet.__dict__.copy()
                        with self.assertRaises(ValueError):
                            wallet.from_wif('invalid')
                        self.assertEqual(wallet.__dict__, before)

    def test_direct_imports_require_mandatory_arguments(self):
        cases = [
            ('from_seed', {}), ('from_seed', {'seed': None}),
            ('from_mnemonic', {}), ('from_mnemonic', {'mnemonic': None}),
            ('from_mnemonic', {'mnemonic': self.root.words, 'passphrase': None}),
            ('from_entropy', {}), ('from_entropy', {'entropy': None}),
            ('from_entropy', {'entropy': bytes(16), 'passphrase': None}),
            ('from_entropy', {'entropy': bytes(16), 'language': None}),
            ('from_private_key', {}), ('from_private_key', {'private_key': None}),
            ('from_extended_private_key', {'private_key': self.root.private_key}),
            ('from_extended_private_key', {'chain_code': self.root.chain_code}),
            ('from_extended_private_key', {'private_key': None, 'chain_code': self.root.chain_code}),
            ('from_extended_private_key', {'private_key': self.root.private_key, 'chain_code': None}),
            ('from_wif', {}), ('from_wif', {'wif': None}),
        ]
        wallet = self.create(entropy=bytes(16), passphrase='original', main_net=False)
        before = wallet.__dict__.copy()
        for method, arguments in cases:
            with self.subTest(method=method, arguments=arguments):
                with self.assertRaises(TypeError):
                    getattr(wallet, method)(**arguments)
                self.assertEqual(wallet.__dict__, before)

    def test_invalid_direct_imports_preserve_state(self):
        cases = [
            ('from_seed', {'seed': 'seed'}, TypeError),
            ('from_mnemonic', {'mnemonic': 123}, TypeError),
            ('from_mnemonic', {'mnemonic': 'not a mnemonic'}, ValueError),
            ('from_mnemonic', {'mnemonic': 'abandon ' * 11 + 'abandon'}, ValueError),
            ('from_entropy', {'entropy': '00' * 16}, TypeError),
            ('from_entropy', {'entropy': bytes(15)}, ValueError),
            ('from_entropy', {'entropy': bytes(16), 'language': 'unknown'}, ValueError),
            ('from_private_key', {'private_key': 'key'}, TypeError),
            ('from_private_key', {'private_key': bytes(31)}, ValueError),
            ('from_private_key', {'private_key': bytes(32)}, ValueError),
            ('from_extended_private_key', {'private_key': bytes(31), 'chain_code': bytes(32)}, ValueError),
            ('from_extended_private_key', {'private_key': self.root.private_key, 'chain_code': 'code'}, TypeError),
            ('from_wif', {'wif': b'wif'}, TypeError),
            ('from_wif', {'wif': 'invalid'}, ValueError),
        ]
        wallet = self.create(entropy=bytes(16), passphrase='original', main_net=False)
        before = wallet.__dict__.copy()
        for method, arguments, error in cases:
            with self.subTest(method=method, arguments=arguments):
                with self.assertRaises(error):
                    getattr(wallet, method)(**arguments)
                self.assertEqual(wallet.__dict__, before)

    def test_valid_direct_imports_match_constructor_results(self):
        cases = [
            ('from_seed', {'seed': self.root.seed}),
            ('from_mnemonic', {'mnemonic': self.root.words}),
            ('from_entropy', {'entropy': bytes(16)}),
            ('from_private_key', {'private_key': self.root.private_key}),
            ('from_extended_private_key', {'private_key': self.root.private_key, 'chain_code': self.root.chain_code}),
            ('from_wif', {'wif': self.root.wif}),
        ]
        for method, arguments in cases:
            with self.subTest(method=method):
                wallet = self.create(entropy=bytes(32), passphrase='old')
                expected = self.create(**arguments)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertIsNone(getattr(wallet, method)(**arguments))
                self.assertEqual(wallet.__dict__, expected.__dict__)


if __name__ == '__main__':
    unittest.main()
