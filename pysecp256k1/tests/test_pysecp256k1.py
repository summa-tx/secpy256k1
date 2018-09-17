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
            secp256k1_ctx = pysecp256k1.context_create(flags)

            self.assertEqual(
                pysecp256k1.ffi.typeof(secp256k1_ctx),
                pysecp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # TODO: Errors if given incorrect context
