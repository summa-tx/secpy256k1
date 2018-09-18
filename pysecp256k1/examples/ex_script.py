import os
import pysecp256k1
pubkey = bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')   # noqa: E501
uncomp_pubkey = bytes.fromhex('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')    # noqa: E501
tweak = bytes.fromhex('aca0338ffd29daeb82021b179348db68ad0740d66698264d2e69e1ae9ab007f1')  # noqa: E501

flags = pysecp256k1.lib.SECP256K1_CONTEXT_VERIFY
secp256k1_ctx = pysecp256k1.context_create(flags)
secp256k1_ctx_clone = pysecp256k1.context_clone(secp256k1_ctx)
secp256k1_pubkey_tuple = pysecp256k1.ec_pubkey_parse(secp256k1_ctx, pubkey)

compression_flag = pysecp256k1.lib.SECP256K1_EC_COMPRESSED
output = pysecp256k1.ec_pubkey_serialize(
        secp256k1_ctx,
        secp256k1_pubkey_tuple[1],
        compression_flag)
pubkey_ser = bytes(pysecp256k1.ffi.buffer(output))

pubkey_tweak_tuple = pysecp256k1.ec_pubkey_tweak_add(
        secp256k1_ctx,
        secp256k1_pubkey_tuple[1],
        tweak)
pubkey_tweak = pubkey_tweak_tuple[1]
pubkey_tweak_hex = bytes(pysecp256k1.ffi.buffer(pubkey_tweak)).hex()

flags = pysecp256k1.lib.SECP256K1_CONTEXT_SIGN
secp256k1_ctx = pysecp256k1.context_create(flags)
seckey = os.urandom(32)
msg = os.urandom(32)
noncefp = pysecp256k1.ffi.NULL
ndata = pysecp256k1.ffi.NULL
sign = pysecp256k1.ecdsa_sign(secp256k1_ctx, msg, seckey, noncefp, ndata)

# invalid sig but function still works
flags = pysecp256k1.lib.SECP256K1_CONTEXT_VERIFY
secp256k1_ctx = pysecp256k1.context_create(flags)
pysecp256k1.ecdsa_verify(secp256k1_ctx, sign, msg, secp256k1_pubkey_tuple[1])
