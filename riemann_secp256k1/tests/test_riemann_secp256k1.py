import unittest
import riemann_secp256k1


class TestRiemannSecp256k1(unittest.TestCase):

    def setUp(self):
        self.context_flags = [
            riemann_secp256k1.lib.SECP256K1_CONTEXT_VERIFY,
            riemann_secp256k1.lib.SECP256K1_CONTEXT_SIGN,
            riemann_secp256k1.lib.SECP256K1_CONTEXT_NONE
        ]
        self.pubkey = bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')   # noqa: E501
        self.uncomp_pubkey = bytes.fromhex('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')    # noqa: E501
        self.tweak = bytes.fromhex('aca0338ffd29daeb82021b179348db68ad0740d66698264d2e69e1ae9ab007f1')  # noqa: E501

    def test_secp256k1_create_context(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = riemann_secp256k1.context_create(flags)

            # Returns a secp256k1_context type
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(secp256k1_ctx),
                riemann_secp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx = riemann_secp256k1.context_create(0)

        self.assertIn('Invalid context flag.', str(err.exception))

    def test_context_clone(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = riemann_secp256k1.context_create(flags)

            # Clone context
            secp256k1_ctx_clone = riemann_secp256k1.context_clone(secp256k1_ctx)

            # Returns a cloned secp256k1_context type
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(secp256k1_ctx_clone),
                riemann_secp256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if invalid context
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx_clone = riemann_secp256k1.context_clone(0)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

    @unittest.skip('TODO')
    def test_context_destroy(self):
        pass

    def test_ec_pubkey_parse(self):
        for flags in self.context_flags:
            # Create context
            ctx = riemann_secp256k1.context_create(flags)

            # Parse variable length public key from bytes
            secp256k1_pubkey_tuple = riemann_secp256k1.ec_pubkey_parse(
                ctx, self.pubkey)

            # First tuple entry returns a 1 for a fully valid public key
            self.assertEqual(secp256k1_pubkey_tuple[0], 1)

            # Second tuple entry returns a pointer to a secp256k1_pubkey
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(secp256k1_pubkey_tuple[1]),
                riemann_secp256k1.ffi.typeof('secp256k1_pubkey *'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            riemann_secp256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            riemann_secp256k1.ec_pubkey_parse(ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

    def test_ec_pubkey_serialize(self):
        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = riemann_secp256k1.context_create(flags)

            # Create COMPRESSED secp256k1_pubkey object to serialize
            secp256k1_pubkey_tuple = riemann_secp256k1.ec_pubkey_parse(
                secp256k1_ctx,
                self.pubkey)
            secp256k1_pubkey = secp256k1_pubkey_tuple[1]

            # Serialize COMPRESSED pubkey
            pubkey_ser_tuple = riemann_secp256k1.ec_pubkey_serialize(
                secp256k1_ctx,
                secp256k1_pubkey,
                riemann_secp256k1.lib.SECP256K1_EC_COMPRESSED)
            pubkey_int = pubkey_ser_tuple[0]
            pubkey_ser = pubkey_ser_tuple[1]
            pubkeylen = pubkey_ser_tuple[2]

            # First tuple entry always returns 1
            self.assertEqual(pubkey_int, 1)

            # Second tuple entry returns type char[] pointer to COMPRESSED
            # public key byte array
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(pubkey_ser),
                riemann_secp256k1.ffi.typeof('char[]'))

            self.assertEqual(riemann_secp256k1.ffi.sizeof(pubkey_ser), 33)

            # Third tuple entry returns type size_t* pointer to public key size
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(pubkeylen),
                riemann_secp256k1.ffi.typeof('size_t*'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            riemann_secp256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            riemann_secp256k1.ec_pubkey_parse(secp256k1_ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = riemann_secp256k1.context_create(flags)

            # Create UNCOMPRESSED secp256k1_pubkey object to serialize
            secp256k1_pubkey_tuple = riemann_secp256k1.ec_pubkey_parse(
                secp256k1_ctx,
                self.uncomp_pubkey)
            secp256k1_pubkey = secp256k1_pubkey_tuple[1]

            # Serialize UNCOMPRESSED pubkey
            pubkey_ser_tuple = riemann_secp256k1.ec_pubkey_serialize(
                secp256k1_ctx,
                secp256k1_pubkey,
                riemann_secp256k1.lib.SECP256K1_EC_UNCOMPRESSED)
            pubkey_int = pubkey_ser_tuple[0]
            pubkey_ser = pubkey_ser_tuple[1]
            pubkeylen = pubkey_ser_tuple[2]

            # First tuple entry always returns 1
            self.assertEqual(pubkey_int, 1)

            # Second tuple entry returns type char[] pointer to UNCOMPRESSED
            # public key byte array
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(pubkey_ser),
                riemann_secp256k1.ffi.typeof('char[]'))

            self.assertEqual(riemann_secp256k1.ffi.sizeof(pubkey_ser), 65)

            # Third tuple entry returns type size_t* pointer to public key size
            self.assertEqual(
                riemann_secp256k1.ffi.typeof(pubkeylen),
                riemann_secp256k1.ffi.typeof('size_t*'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            riemann_secp256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            riemann_secp256k1.ec_pubkey_parse(secp256k1_ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

    @unittest.skip('TODO')
    def test_ecdsa_signature_parse_compact(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_signature_parse_der(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_signature_serialize_der(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_signature_serialize_compact(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_verify(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_signature_normalize(self):
        pass

    @unittest.skip('TODO')
    def test_ecdsa_sign(self):
        pass

    @unittest.skip('TODO')
    def test_ec_seckey_verify(self):
        pass

    @unittest.skip('TODO')
    def test_ec_pubkey_create(self):
        pass

    @unittest.skip('TODO')
    def test_ec_privkey_negate(self):
        pass

    @unittest.skip('TODO')
    def test_ec_pubkey_negate(self):
        pass

    def test_ec_privkey_tweak_add(self):
        # Create context
        secp256k1_ctx = riemann_secp256k1.context_create(
            riemann_secp256k1.lib.SECP256K1_CONTEXT_VERIFY)

        # Create COMPRESSED secp256k1_pubkey object to add tweak
        secp256k1_pubkey_tuple = riemann_secp256k1.ec_pubkey_parse(
            secp256k1_ctx,
            self.pubkey)
        secp256k1_pubkey = secp256k1_pubkey_tuple[1]

        # Tweaked secp256k1_pubkey
        secp256k1_pubkey_tweak_tuple = riemann_secp256k1.ec_pubkey_tweak_add(
            secp256k1_ctx,
            secp256k1_pubkey,
            self.tweak)

        # First tuple entry returns a 1 for a fully valid public key
        self.assertEqual(secp256k1_pubkey_tweak_tuple[0], 1)

        # Second tuple entry returns a tweaked secp256k1_pubkey pointer type
        self.assertEqual(
            riemann_secp256k1.ffi.typeof(secp256k1_pubkey_tweak_tuple[1]),
            riemann_secp256k1.ffi.typeof('secp256k1_pubkey *'))

        # Errors if invalid context
        with self.assertRaises(TypeError) as err:
            riemann_secp256k1.ec_pubkey_tweak_add(0, self.pubkey, self.tweak)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid pubkey
        with self.assertRaises(TypeError) as err:
            riemann_secp256k1.ec_pubkey_tweak_add(
                secp256k1_ctx,
                self.pubkey,
                self.tweak)

        self.assertIn(
            'Invalid pubkey. Must be secp256k1_pubkey pointer.',
            str(err.exception))

        # Errors if invalid tweak
        with self.assertRaises(ValueError) as err:
            riemann_secp256k1.ec_pubkey_tweak_add(
                secp256k1_ctx,
                secp256k1_pubkey,
                bytes.fromhex('00000001'))

        self.assertIn(
            'Invalid tweak. Must be 32-bytes.',
            str(err.exception))

    @unittest.skip('TODO')
    def test_ec_pubkey_tweak_add(self):
        pass

    @unittest.skip('TODO')
    def test_ec_privkey_tweak_mul(self):
        pass

    @unittest.skip('TODO')
    def test_ec_pubkey_tweak_mul(self):
        pass

    @unittest.skip('TODO')
    def test_context_randomize(self):
        pass

    @unittest.skip('TODO')
    def test_ec_pubkey_combine(self):
        pass

    @unittest.skip('TODO')
    def test_validate_context(self):
        pass

    @unittest.skip('TODO')
    def test_valide_public_key(self):
        pass

    @unittest.skip('TODO')
    def test_validate_cdata_type(self):
        pass
