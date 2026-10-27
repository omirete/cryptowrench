"""Private-key scalar boundaries and wallet import validation."""

import contextlib
import io
import unittest
from unittest.mock import patch

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.elliptic_math import SECP256K1_Helpers
from cryptowrench.wallet.helpers.key_validation import _is_valid_private_key


class PrivateKeyValidationTests(unittest.TestCase):
    def test_valid_scalar_boundaries(self):
        for scalar in (1, SECP256K1_Helpers.order - 1):
            key = scalar.to_bytes(32, 'big')
            with self.subTest(scalar=scalar), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(_is_valid_private_key(key))
                wallet = Wallet(private_key=key)
                self.assertEqual(wallet.private_key, key)
                self.assertEqual(len(wallet.public_key), 33)
                extended = Wallet(private_key=key, chain_code=bytes(32))
                self.assertEqual(extended.public_key, wallet.public_key)

    def test_invalid_scalars(self):
        for scalar in (0, SECP256K1_Helpers.order, SECP256K1_Helpers.order + 1, 2**256 - 1):
            with self.subTest(scalar=scalar):
                self.assertFalse(_is_valid_private_key(scalar.to_bytes(32, 'big')))

    def test_invalid_types_and_lengths_return_false(self):
        for value in (None, 1, True, '0' * 32, [], bytearray(32), memoryview(bytes(32)),
                      b'', bytes(16), bytes(31), bytes(33)):
            with self.subTest(value=value):
                self.assertFalse(_is_valid_private_key(value))

    def test_invalid_imports_preserve_state_without_deriving_public_keys(self):
        wallet = Wallet(entropy=bytes(16), passphrase='original', main_net=False)
        before = wallet.__dict__.copy()
        invalid = [scalar.to_bytes(32, 'big') for scalar in
                   (0, SECP256K1_Helpers.order, SECP256K1_Helpers.order + 1, 2**256 - 1)]
        invalid.extend((bytes(31), bytes(33)))
        for key in invalid:
            for extended in (False, True):
                arguments = {'private_key': key}
                if extended:
                    arguments['chain_code'] = bytes(32)
                with self.subTest(key=key.hex(), extended=extended):
                    with patch('cryptowrench.wallet.main.get_public_key') as derive:
                        with self.assertRaises(ValueError):
                            Wallet(**arguments)
                        method = wallet.from_extended_private_key if extended else wallet.from_private_key
                        with self.assertRaises(ValueError):
                            method(**arguments)
                        derive.assert_not_called()
                    self.assertEqual(wallet.__dict__, before)


if __name__ == '__main__':
    unittest.main()
