import secpy256k1

SECP256K1_CONTEXT_SIGN = secpy256k1.lib.SECP256K1_CONTEXT_SIGN
SECP256K1_CONTEXT_VERIFY = secpy256k1.lib.SECP256K1_CONTEXT_VERIFY
SECP256K1_EC_COMPRESSED = secpy256k1.lib.SECP256K1_EC_COMPRESSED

privkey = b'\x32' * 32
pubkey = bytes.fromhex('0290999dbbf43034bffb1dd53eac1eb4c33a4ea1c4f48ba585cfde3830840f0555')   # noqa: E501
uncomp_pubkey = bytes.fromhex('0490999dbbf43034bffb1dd53eac1eb4c33a4ea1c4f48ba585cfde3830840f05553a9d6d07e79ae2fbe0bc0b20c93e1f8e20d74b8a0a7028e32d9a6808b6c38df4')    # noqa: E501
tweak = b'\x66' * 32  # noqa: E501
msg = bytes.fromhex('deadbeef' * 8)

verify_context = secpy256k1.context_create(SECP256K1_CONTEXT_VERIFY)
sign_context = secpy256k1.context_create(SECP256K1_CONTEXT_SIGN)

# try cloning to make sure it doesn't error
secpy256k1.context_clone(verify_context)

# parse the pubkey to a secpy pubkey tuple
secp256k1_pubkey_tuple = secpy256k1.ec_pubkey_parse(verify_context, pubkey)

# serialize the pubkey
output_tuple = secpy256k1.ec_pubkey_serialize(
    verify_context,
    secp256k1_pubkey_tuple[1],
    SECP256K1_EC_COMPRESSED)

ser_pub = output_tuple[1]
pubkey_ser = bytes(secpy256k1.ffi.buffer(ser_pub))
print('\n\npubkey_ser', pubkey_ser.hex())

# check pubkey tweak function
tweaked_pubkey_tuple = secpy256k1.ec_pubkey_tweak_add(
    verify_context,
    secpy256k1.ec_pubkey_parse(verify_context, pubkey)[1],
    tweak)
tweaked_pubkey = tweaked_pubkey_tuple[1]
output_tweak_tuple = secpy256k1.ec_pubkey_serialize(
    verify_context,
    secpy256k1.ec_pubkey_parse(verify_context, pubkey)[1],
    SECP256K1_EC_COMPRESSED)
tweaked_pubkey_chars = output_tweak_tuple[1]
print('\n\ntweaked_pubkey',
      bytes(secpy256k1.ffi.buffer(tweaked_pubkey_chars)).hex())

sign_tuple = secpy256k1.ecdsa_sign(
    sign_context, msg, privkey)
result = sign_tuple[0]
signature = sign_tuple[1]

print('\n\nsign', bytes(secpy256k1.ffi.buffer(signature)).hex())


der_sig = secpy256k1.ecdsa_signature_serialize_der(
    sign_context, signature)[1]
print('\n\ndersig',
      bytes(secpy256k1.ffi.buffer(der_sig)).hex())

compact_sig = secpy256k1.ecdsa_signature_serialize_compact(
    sign_context, signature)[1]
print('\n\ncompactsig',
      bytes(secpy256k1.ffi.buffer(compact_sig)).hex())

# invalid sig but function still works
print('\n\necdsa_verify', secpy256k1.ecdsa_verify(
    verify_context, signature, msg, secp256k1_pubkey_tuple[1]))


sig = bytes.fromhex('3045022100a9e1adada9644225f11ed152d6ba81c52f594efc9e8fd35c636926320bb2d77402201c39cf35e5e898a52c6d50e75047f18c939783e70cec8df2e7d1d32b446ef3fd')   # noqa: E501
ecdsa_parsed_sig_tuple = secpy256k1.ecdsa_signature_parse_der(
    verify_context, sig)
secp256k1_sig = ecdsa_parsed_sig_tuple[1]
print('\n\nsecpy256k1_sig', bytes(secpy256k1.ffi.buffer(secp256k1_sig)).hex())

# secpy256k1.ec_seckey_verify(verify_context, os.urandom(32))
# secpy256k1.ec_pubkey_create(secp256k1_ctx, os.urandom(32))
# secpy256k1.ec_privkey_negate(secp256k1_ctx, os.urandom(32))
# secpy256k1.ec_privkey_tweak_mul(secp256k1_ctx, os.urandom(32), tweak)
