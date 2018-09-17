import os
import _secp256k1
import pysecp256k1

#  ctx = _secp256k1.lib.SECP256K1_CONTEXT_NONE
ctx = _secp256k1.lib.SECP256K1_CONTEXT_VERIFY
secp256k1_ctx = pysecp256k1.context_create(ctx)

pubkey = bytes.fromhex(
        '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')
secp256k1_pubkey = pysecp256k1.ec_pubkey_parse(secp256k1_ctx, pubkey)

compression_flag = pysecp256k1.lib.SECP256K1_EC_COMPRESSED
output= pysecp256k1.ec_pubkey_serialize(
        secp256k1_ctx,
        secp256k1_pubkey,
        compression_flag)
pubkey_ser = bytes(pysecp256k1.ffi.buffer(output))

tweak = os.urandom(32)
pubkey_tweak = pysecp256k1.ec_pubkey_tweak_add(secp256k1_ctx, secp256k1_pubkey, tweak)
pubkey_tweak_hex = bytes(pysecp256k1.ffi.buffer(pubkey_tweak)).hex()
