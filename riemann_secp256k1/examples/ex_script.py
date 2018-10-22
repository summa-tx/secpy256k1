import os
import riemann_secp256k1

pubkey = bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')   # noqa: E501
uncomp_pubkey = bytes.fromhex('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')    # noqa: E501
tweak = bytes.fromhex('aca0338ffd29daeb82021b179348db68ad0740d66698264d2e69e1ae9ab007f1')  # noqa: E501

flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_VERIFY
secp256k1_ctx = riemann_secp256k1.context_create(flags)
secp256k1_ctx_clone = riemann_secp256k1.context_clone(secp256k1_ctx)
secp256k1_pubkey_tuple = riemann_secp256k1.ec_pubkey_parse(secp256k1_ctx, pubkey)

compression_flag = riemann_secp256k1.lib.SECP256K1_EC_COMPRESSED
output_tuple = riemann_secp256k1.ec_pubkey_serialize(
        secp256k1_ctx,
        secp256k1_pubkey_tuple[1],
        compression_flag)

output_int = output_tuple[0]
output = output_tuple[1]
ouputlen = output_tuple[2]
pubkey_ser = bytes(riemann_secp256k1.ffi.buffer(output))

# Pubkey Tweak Add
pubkey_tweak_tuple = riemann_secp256k1.ec_pubkey_tweak_add(
        secp256k1_ctx,
        secp256k1_pubkey_tuple[1],
        tweak)
pubkey_tweak = pubkey_tweak_tuple[1]
output_tweak_tuple = riemann_secp256k1.ec_pubkey_serialize(
        secp256k1_ctx,
        secp256k1_pubkey_tuple[1],
        compression_flag)
output_tweak_int = output_tweak_tuple[0]
output_tweak = output_tweak_tuple[1]
ouputlen_tweak = output_tweak_tuple[2]
pubkey_tweak_ser = bytes(riemann_secp256k1.ffi.buffer(output_tweak))
pubkey_tweak_hex = pubkey_tweak_ser.hex()


flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_SIGN
secp256k1_ctx = riemann_secp256k1.context_create(flags)
seckey = os.urandom(32)
msg = os.urandom(32)
noncefp = riemann_secp256k1.ffi.NULL
ndata = riemann_secp256k1.ffi.NULL
sign_tuple = riemann_secp256k1.ecdsa_sign(secp256k1_ctx, msg, seckey, noncefp, ndata)
sign = sign_tuple[1]

# invalid sig but function still works
flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_VERIFY
secp256k1_ctx = riemann_secp256k1.context_create(flags)
riemann_secp256k1.ecdsa_verify(secp256k1_ctx, sign, msg, secp256k1_pubkey_tuple[1])

sig = bytes.fromhex('483045022100e222a0a6816475d85ad28fbeb66e97c931081076dc9655da3afc6c1d81b43f9802204681f9ea9d52a31c9c47cf78b71410ecae6188d7c31495f5f1adfe0df5864a7401')   # noqa: E501
ecdsa_parsed_sig_tuple = riemann_secp256k1.ecdsa_signature_parse_der(
    secp256k1_ctx, sig)
secp256k1_sig = ecdsa_parsed_sig_tuple[1]

ecdsa_sig_ser_tuple = riemann_secp256k1.ecdsa_signature_serialize_der(
    secp256k1_ctx, secp256k1_sig)
ecdsa_sig_ser_int = ecdsa_sig_ser_tuple[0]
ecdsa_sig_ser_output = ecdsa_sig_ser_tuple[1]
ecdsa_sig_ser_outputlen = ecdsa_sig_ser_tuple[2]
bytes(riemann_secp256k1.ffi.buffer(ecdsa_sig_ser_output)).hex()
bytes(riemann_secp256k1.ffi.buffer(ecdsa_sig_ser_outputlen)).hex()


riemann_secp256k1.ec_seckey_verify(secp256k1_ctx, os.urandom(32))
flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_SIGN
secp256k1_ctx = riemann_secp256k1.context_create(flags)
riemann_secp256k1.ec_pubkey_create(secp256k1_ctx, os.urandom(32))
riemann_secp256k1.ec_privkey_negate(secp256k1_ctx, os.urandom(32))

riemann_secp256k1.ec_privkey_tweak_mul(secp256k1_ctx, os.urandom(32), tweak)
