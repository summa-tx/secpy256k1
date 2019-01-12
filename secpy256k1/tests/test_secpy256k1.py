import unittest
import secpy256k1


class TestSecpy256k1(unittest.TestCase):

    def setUp(self):
        self.context_flags = [
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY,
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN,
            secpy256k1.lib.SECP256K1_CONTEXT_NONE
        ]

        self.privkey = b'\x32' * 32
        self.pubkey = bytes.fromhex('0290999dbbf43034bffb1dd53eac1eb4c33a4ea1c4f48ba585cfde3830840f0555')  # noqa: E501
        self.uncomp_pubkey = bytes.fromhex('0490999dbbf43034bffb1dd53eac1eb4c33a4ea1c4f48ba585cfde3830840f05553a9d6d07e79ae2fbe0bc0b20c93e1f8e20d74b8a0a7028e32d9a6808b6c38df4')  # noqa: E501
        self.msg = bytes.fromhex('deadbeef' * 8)
        self.der_sig = bytes.fromhex('3045022100a9e1adada9644225f11ed152d6ba81c52f594efc9e8fd35c636926320bb2d77402201c39cf35e5e898a52c6d50e75047f18c939783e70cec8df2e7d1d32b446ef3fd')  # noqa: E501
        self.compact_sig = bytes.fromhex('a9e1adada9644225f11ed152d6ba81c52f594efc9e8fd35c636926320bb2d7741c39cf35e5e898a52c6d50e75047f18c939783e70cec8df2e7d1d32b446ef3fd')  # noqa: E501
        self.buffer_sig = bytes.fromhex('74d7b20b322669635cd38f9efc4e592fc581bad652d11ef1254264a9adade1a9fdf36e442bd3d1e7f28dec0ce78397938cf14750e7506d2ca598e8e535cf391c')  # noqa: E501
        self.tweak = b'\x66' * 32

    def test_secp256k1_create_context(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = secpy256k1.context_create(flags)

            # Returns a secp256k1_context type
            self.assertEqual(
                secpy256k1.ffi.typeof(secp256k1_ctx),
                secpy256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx = secpy256k1.context_create(0)

        self.assertIn('Invalid context flag.', str(err.exception))

    def test_context_clone(self):

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = secpy256k1.context_create(flags)

            # Clone context
            secp256k1_ctx_clone = secpy256k1.context_clone(secp256k1_ctx)

            # Returns a cloned secp256k1_context type
            self.assertEqual(
                secpy256k1.ffi.typeof(secp256k1_ctx_clone),
                secpy256k1.ffi.typeof('struct secp256k1_context_struct *'))

        # Errors if invalid context
        with self.assertRaises(TypeError) as err:
            secp256k1_ctx_clone = secpy256k1.context_clone(0)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

    @unittest.skip('TODO')
    def test_context_destroy(self):
        pass

    def test_ec_pubkey_parse(self):
        for flags in self.context_flags:
            # Create context
            ctx = secpy256k1.context_create(flags)

            # Parse variable length public key from bytes
            secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(
                ctx, self.pubkey)

            # First tuple entry returns a 1 for a fully valid public key
            self.assertEqual(secp256k1_pubkey_tuple[0], 1)

            # Second tuple entry returns a pointer to a secp256k1_pubkey
            self.assertEqual(
                secpy256k1.ffi.typeof(secp256k1_pubkey_tuple[1]),
                secpy256k1.ffi.typeof('secp256k1_pubkey *'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            secpy256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            secpy256k1.ec_pubkey_parse(ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

    def test_ec_pubkey_serialize(self):
        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = secpy256k1.context_create(flags)

            # Create COMPRESSED secp256k1_pubkey object to serialize
            secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(
                secp256k1_ctx,
                self.pubkey)
            secp256k1_pubkey = secp256k1_pubkey_tuple[1]

            # Serialize COMPRESSED pubkey
            pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
                secp256k1_ctx,
                secp256k1_pubkey,
                secpy256k1.lib.SECP256K1_EC_COMPRESSED)
            pubkey_int = pubkey_ser_tuple[0]
            pubkey_ser = pubkey_ser_tuple[1]
            pubkeylen = pubkey_ser_tuple[2]

            # First tuple entry always returns 1
            self.assertEqual(pubkey_int, 1)

            # Second tuple entry returns type char[] pointer to COMPRESSED
            # public key byte array
            self.assertEqual(
                secpy256k1.ffi.typeof(pubkey_ser),
                secpy256k1.ffi.typeof('char[]'))

            self.assertEqual(secpy256k1.ffi.sizeof(pubkey_ser), 33)

            # Third tuple entry returns type size_t* pointer to public key size
            self.assertEqual(
                secpy256k1.ffi.typeof(pubkeylen),
                secpy256k1.ffi.typeof('size_t*'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            secpy256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            secpy256k1.ec_pubkey_parse(secp256k1_ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

        for flags in self.context_flags:
            # Create context
            secp256k1_ctx = secpy256k1.context_create(flags)

            # Create UNCOMPRESSED secp256k1_pubkey object to serialize
            secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(
                secp256k1_ctx,
                self.uncomp_pubkey)
            secp256k1_pubkey = secp256k1_pubkey_tuple[1]

            # Serialize UNCOMPRESSED pubkey
            pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
                secp256k1_ctx,
                secp256k1_pubkey,
                secpy256k1.lib.SECP256K1_EC_UNCOMPRESSED)
            pubkey_int = pubkey_ser_tuple[0]
            pubkey_ser = pubkey_ser_tuple[1]
            pubkeylen = pubkey_ser_tuple[2]

            # First tuple entry always returns 1
            self.assertEqual(pubkey_int, 1)

            # Second tuple entry returns type char[] pointer to UNCOMPRESSED
            # public key byte array
            self.assertEqual(
                secpy256k1.ffi.typeof(pubkey_ser),
                secpy256k1.ffi.typeof('char[]'))

            self.assertEqual(secpy256k1.ffi.sizeof(pubkey_ser), 65)

            # Third tuple entry returns type size_t* pointer to public key size
            self.assertEqual(
                secpy256k1.ffi.typeof(pubkeylen),
                secpy256k1.ffi.typeof('size_t*'))

        # Errors if invalid context flag
        with self.assertRaises(TypeError) as err:
            secpy256k1.ec_pubkey_parse(0, self.pubkey)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid seralized public key
        with self.assertRaises(ValueError) as err:
            secpy256k1.ec_pubkey_parse(secp256k1_ctx, 0)

        self.assertIn(
            'Invalid pubkey. Must be 33- or 65-bytes.',
            str(err.exception))

    def test_ecdsa_signature_parse_compact(self):
        verify_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)

        parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_compact(
            verify_context,
            self.compact_sig)

        parsed_sig = bytes(secpy256k1.ffi.buffer(parsed_sig_tuple[1]))

        self.assertEqual(parsed_sig_tuple[0], 1)
        self.assertEqual(parsed_sig, self.buffer_sig)

    def test_ecdsa_signature_parse_der(self):
        verify_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)

        parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_der(
            verify_context,
            self.der_sig)

        parsed_sig = bytes(secpy256k1.ffi.buffer(parsed_sig_tuple[1]))

        self.assertEqual(parsed_sig_tuple[0], 1)
        self.assertEqual(parsed_sig, self.buffer_sig)

    def test_ecdsa_signature_serialize_der(self):
        verify_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)
        sign_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN)

        parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_der(
            verify_context,
            self.der_sig)

        der_sig_tuple = secpy256k1.ecdsa_signature_serialize_der(
            sign_context,
            parsed_sig_tuple[1])

        der_sig = bytes(secpy256k1.ffi.buffer(der_sig_tuple[1]))

        self.assertEqual(der_sig_tuple[0], 1)
        self.assertEqual(der_sig, self.der_sig)

    def test_ecdsa_signature_serialize_compact(self):
        verify_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)
        sign_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN)

        parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_compact(
            verify_context,
            self.compact_sig)

        compact_sig_tuple = secpy256k1.ecdsa_signature_serialize_compact(
            sign_context,
            parsed_sig_tuple[1])

        compact_sig = bytes(secpy256k1.ffi.buffer(compact_sig_tuple[1]))

        self.assertEqual(compact_sig_tuple[0], 1)
        self.assertEqual(compact_sig, self.compact_sig)

    def test_ecdsa_verify(self):
        verify_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)

        parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_compact(
            verify_context,
            self.compact_sig)

        secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(
            verify_context,
            self.pubkey)

        verify_res = secpy256k1.ecdsa_verify(
            verify_context,
            parsed_sig_tuple[1],
            self.msg,
            secp256k1_pubkey_tuple[1])

        self.assertEqual(verify_res, 1)

    @unittest.skip('TODO')
    def test_ecdsa_signature_normalize(self):
        pass

    def test_ecdsa_sign(self):
        sign_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN)
        sign_tuple = secpy256k1.ecdsa_sign(
            sign_context,
            self.msg,
            self.privkey)
        buffer_sig = bytes(secpy256k1.ffi.buffer(sign_tuple[1]))

        self.assertEqual(sign_tuple[0], 1)
        self.assertEqual(buffer_sig, self.buffer_sig)

    def test_ec_seckey_verify(self):
        sign_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN)
        self.assertEqual(
            secpy256k1.ec_seckey_verify(sign_context, self.privkey),
            1)
        self.assertEqual(
            secpy256k1.ec_seckey_verify(sign_context, b'\x00' * 32),
            0)

    def test_ec_pubkey_create(self):
        sign_context = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_SIGN)

        pubkey_tuple = secpy256k1.ec_pubkey_create(
            sign_context,
            self.privkey)

        pubkey_compressed_ser = secpy256k1.ec_pubkey_serialize(
            sign_context,
            pubkey_tuple[1],
            secpy256k1.lib.SECP256K1_EC_COMPRESSED)

        pubkey = bytes(secpy256k1.ffi.buffer(pubkey_compressed_ser[1]))

        self.assertEqual(pubkey_tuple[0], 1)
        self.assertEqual(pubkey, self.pubkey)

    @unittest.skip('TODO')
    def test_ec_privkey_negate(self):
        pass

    @unittest.skip('TODO')
    def test_ec_pubkey_negate(self):
        pass

    def test_ec_privkey_tweak_add(self):
        # Create context
        secp256k1_ctx = secpy256k1.context_create(
            secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)

        # Create COMPRESSED secp256k1_pubkey object to add tweak
        secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(
            secp256k1_ctx,
            self.pubkey)
        secp256k1_pubkey = secp256k1_pubkey_tuple[1]

        # Tweaked secp256k1_pubkey
        secp256k1_pubkey_tweak_tuple = secpy256k1.ec_pubkey_tweak_add(
            secp256k1_ctx,
            secp256k1_pubkey,
            self.tweak)

        # First tuple entry returns a 1 for a fully valid public key
        self.assertEqual(secp256k1_pubkey_tweak_tuple[0], 1)

        # Second tuple entry returns a tweaked secp256k1_pubkey pointer type
        self.assertEqual(
            secpy256k1.ffi.typeof(secp256k1_pubkey_tweak_tuple[1]),
            secpy256k1.ffi.typeof('secp256k1_pubkey *'))

        # Errors if invalid context
        with self.assertRaises(TypeError) as err:
            secpy256k1.ec_pubkey_tweak_add(0, self.pubkey, self.tweak)

        self.assertIn(
            'Invalid context. Must be secp256k1_context_struct pointer.',
            str(err.exception))

        # Errors if invalid pubkey
        with self.assertRaises(TypeError) as err:
            secpy256k1.ec_pubkey_tweak_add(
                secp256k1_ctx,
                self.pubkey,
                self.tweak)

        self.assertIn(
            'Invalid pubkey. Must be secp256k1_pubkey pointer.',
            str(err.exception))

        # Errors if invalid tweak
        with self.assertRaises(ValueError) as err:
            secpy256k1.ec_pubkey_tweak_add(
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
