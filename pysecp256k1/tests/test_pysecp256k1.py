import unittest
import pysecp256k1


class TestPysecp256k1(unittest.TestCase):

    def setUp(self):
        self.context_flags = [
            pysecp256k1.lib.SECP256K1_CONTEXT_VERIFY,
            pysecp256k1.lib.SECP256K1_CONTEXT_SIGN,
            pysecp256k1.lib.SECP256K1_CONTEXT_NONE
        ]

    def test_secp256k1_create_context(self):
        # Returns a secp256k1_context type
        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = pysecp256k1.context_create(flags)

            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_ctx),
                pysecp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if given invalid context flag
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx = pysecp256k1.context_create(0)

        self.assertIn('Invalid context flag.', str(err.exception))

    @unittest.skip('TODO')
    def test_context_clone(self):
        pass

    def test_context_destroy(self):
        # Returns a secp256k1_context type
        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = pysecp256k1.context_create(flags)

            # Clone context
            secp256k1_ctx_clone = pysecp256k1.context_clone(secp256k1_ctx)

            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_ctx_clone),
                pysecp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if given invalid context
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx_clone = pysecp256k1.context_clone(0)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))
