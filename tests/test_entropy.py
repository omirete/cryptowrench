"""Run with: python -m unittest discover -s tests -v."""

import contextlib
import io
import unittest
from unittest.mock import patch

from mnemonic import Mnemonic

from cryptowrench.wallet import Wallet
from test_mnemonics import test_vectors_mnemonic


class EntropyWalletTests(unittest.TestCase):
    entropy = bytes(16)

    def test_published_bip39_vectors(self):
        # Published Trezor BIP39 vectors already kept in this repository.
        for passphrase, entropy, words, seed, xprv in test_vectors_mnemonic['english']:
            entropy = bytes.fromhex(entropy)
            for entrypoint in ('constructor', 'method'):
                with self.subTest(entropy=entropy, entrypoint=entrypoint):
                    if entrypoint == 'constructor':
                        wallet = Wallet(entropy=entropy, passphrase=passphrase)
                    else:
                        wallet = Wallet(seed=bytes(range(16)))
                        self.assertIsNone(wallet.from_entropy(entropy, passphrase))
                    self.assertEqual(wallet.words, words)
                    self.assertEqual(wallet.passphrase, passphrase)
                    self.assertEqual(wallet.seed.hex(), seed)
                    self.assertEqual(wallet.hd_wallet('m').serialized_extended_private_key.decode(), xprv)

    def test_all_entropy_lengths_and_leading_zeros(self):
        for bits, word_count in ((128, 12), (160, 15), (192, 18), (224, 21), (256, 24)):
            with self.subTest(bits=bits):
                entropy = bytes(bits // 8)
                wallet = Wallet(entropy=entropy)
                self.assertEqual(len(wallet.words.split()), word_count)
                self.assertEqual(Mnemonic('english').to_entropy(wallet.words), entropy)
                self.assertEqual(wallet.seed, Wallet(mnemonic=wallet.words).seed)

    def test_raw_bytes_are_not_decoded_as_text_or_hex(self):
        for entropy in (bytes(range(16)), b'0123456789abcdef', b'\xff' * 16,
                        b'\x00\t\n\r ' + bytes(range(11))):
            with self.subTest(entropy=entropy):
                wallet = Wallet(entropy=entropy)
                self.assertEqual(Mnemonic('english').to_entropy(wallet.words), entropy)

    def test_passphrases(self):
        empty = Wallet(entropy=self.entropy)
        explicit_empty = Wallet(entropy=self.entropy, passphrase='')
        protected = Wallet(entropy=self.entropy, passphrase='TREZOR')
        self.assertEqual(empty.seed, explicit_empty.seed)
        self.assertNotEqual(empty.seed, protected.seed)
        self.assertEqual(empty.words, protected.words)
        composed = Wallet(entropy=self.entropy, passphrase='caf\u00e9')
        decomposed = Wallet(entropy=self.entropy, passphrase='cafe\u0301')
        self.assertEqual(composed.seed, decomposed.seed)

    def test_all_installed_languages_without_detection(self):
        for language in Mnemonic.list_languages():
            for entrypoint in ('constructor', 'method'):
                with self.subTest(language=language, entrypoint=entrypoint):
                    wallet = Wallet(seed=bytes(range(16)), main_net=False)
                    with patch.object(Mnemonic, 'detect_language', side_effect=AssertionError('Must use selected language')):
                        if entrypoint == 'constructor':
                            wallet = Wallet(entropy=self.entropy, passphrase='TREZOR', language=language, main_net=False)
                        else:
                            wallet.from_entropy(self.entropy, 'TREZOR', language)
                    words = Mnemonic(language).to_mnemonic(self.entropy)
                    self.assertEqual(wallet.words, words)
                    self.assertTrue(Mnemonic(language).check(wallet.words))
                    self.assertEqual(wallet.seed, Mnemonic.to_seed(words, 'TREZOR'))
                    self.assertTrue(wallet.test_net)
                    if language == 'japanese':
                        self.assertIn('\u3000', wallet.words)

    def test_invalid_entropy_and_state_preservation(self):
        invalid = [bytes(length) for length in range(34) if length not in (16, 20, 24, 28, 32)]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Wallet(entropy=value)
                wallet = Wallet(entropy=self.entropy, passphrase='original')
                before = wallet.__dict__.copy()
                with self.assertRaises(ValueError):
                    wallet.from_entropy(value)
                self.assertEqual(wallet.__dict__, before)

    def test_invalid_types_and_languages_preserve_state(self):
        cases = [({'entropy': value}, TypeError) for value in
                 (None, '', '00' * 16, 123, [], True, bytearray(16), memoryview(bytes(16)))]
        cases += [({'passphrase': value}, TypeError) for value in (None, b'password', 123)]
        cases += [({'language': value}, TypeError) for value in (None, 123, [])]
        cases += [({'language': value}, ValueError) for value in ('', 'unknown', 'English')]
        wallet = Wallet(entropy=self.entropy, passphrase='original')
        before = wallet.__dict__.copy()
        for overrides, error in cases:
            kwargs = {'entropy': self.entropy, **overrides}
            with self.subTest(overrides=overrides):
                with self.assertRaises(error):
                    wallet.from_entropy(**kwargs)
                self.assertEqual(wallet.__dict__, before)
                # Constructor None means omitted; direct imports require concrete values.
                if None not in overrides.values():
                    with self.assertRaises(error):
                        Wallet(**kwargs)

    def test_conflicting_sources(self):
        wallet = Wallet(entropy=self.entropy)
        sources = {'entropy': self.entropy, 'mnemonic': wallet.words,
                   'seed': wallet.seed, 'private_key': wallet.private_key, 'wif': wallet.wif}
        names = list(sources)
        for index, first in enumerate(names):
            for second in names[index + 1:]:
                with self.subTest(first=first, second=second):
                    with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                        Wallet(**{first: sources[first], second: sources[second]})

    def test_strength_and_entropy_are_mutually_exclusive(self):
        wallet = Wallet(entropy=bytes(32))
        self.assertEqual(len(wallet.words.split()), 24)
        for strength in (128, 160, 192, 224, 256, 1):
            with self.subTest(strength=strength):
                with self.assertRaisesRegex(ValueError, "'entropy' and 'strength'"):
                    Wallet(entropy=self.entropy, strength=strength)
        self.assertEqual(len(Wallet().words.split()), 12)
        self.assertEqual(len(Wallet(strength=256).words.split()), 24)
        with self.assertRaises(ValueError):
            Wallet(strength=1)

    def test_existing_wallet_sources_and_hd_derivation(self):
        original = Wallet(entropy=self.entropy, passphrase='TREZOR')
        for wallet in (Wallet(mnemonic=original.words, passphrase='TREZOR'),
                       Wallet(seed=original.seed),
                       Wallet(private_key=original.private_key, chain_code=original.chain_code)):
            self.assertEqual(wallet.private_key, original.private_key)
            self.assertEqual(wallet.chain_code, original.chain_code)
            self.assertEqual(wallet.hd_wallet("m/84'/0'/0'/0/0").address.bitcoin.P2WPKH_wit0,
                             original.hd_wallet("m/84'/0'/0'/0/0").address.bitcoin.P2WPKH_wit0)
        with contextlib.redirect_stdout(io.StringIO()):
            for wallet in (Wallet(private_key=original.private_key), Wallet(wif=original.wif)):
                self.assertEqual(wallet.private_key, original.private_key)
                self.assertIsNone(wallet.chain_code)
            with self.assertRaises(ValueError):
                Wallet(wif='invalid')
        for language in Mnemonic.list_languages():
            with self.subTest(language=language):
                random_wallet = Wallet(strength=160, passphrase='test', language=language)
                self.assertTrue(Mnemonic(language).check(random_wallet.words))
                self.assertEqual(random_wallet.seed, Mnemonic.to_seed(random_wallet.words, 'test'))


if __name__ == '__main__':
    unittest.main()
