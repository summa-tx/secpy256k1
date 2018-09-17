import unittest
import pysecp256k1


class TestPysecp256k1(unittest.TestCase):

    def setUp(self):
        self.context_flags = [
            pysecp256k1.lib.SECP256K1_CONTEXT_VERIFY,
            pysecp256k1.lib.SECP256K1_CONTEXT_SIGN,
            pysecp256k1.lib.SECP256K1_CONTEXT_NONE
        ]
        self.pubkey = bytes.fromhex(
            '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')   # noqa: E501

    def test_secp256k1_create_context(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = pysecp256k1.context_create(flags)

            # Returns a secp256k1_context type
            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_ctx),
                pysecp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if given invalid context flag
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx = pysecp256k1.context_create(0)

        self.assertIn('Invalid context flag.', str(err.exception))

    def test_context_clone(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = pysecp256k1.context_create(flags)

            # Clone context
            secp256k1_ctx_clone = pysecp256k1.context_clone(secp256k1_ctx)

            # Returns a cloned secp256k1_context type
            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_ctx_clone),
                pysecp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if given invalid context
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx_clone = pysecp256k1.context_clone(0)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

    @unittest.skip('TODO')
    def test_context_destroy(self):
        pass

    def test_ec_pubkey_parse(self):
        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = pysecp256k1.context_create(flags)

            # Parse variable length public key from bytes
            secp256k1_pubkey = pysecp256k1.ec_pubkey_parse(
                secp256k1_ctx,
                self.pubkey)

            # Returns a secp256k1_context type
            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_pubkey),
                pysecp256k1.ffi.typeof('secp256k1_pubkey *'))

        # Errors if given invalid context flag
        with self.assertRaises(ValueError) as err:
            secp256k1_ctx = pysecp256k1.ec_pubkey_parse(secp256k1_ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))
