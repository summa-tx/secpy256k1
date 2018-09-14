import _secp256k1
import pysecp256k1

obj = pysecp256k1.Context(_secp256k1.lib.SECP256K1_CONTEXT_NONE)
print(dir(obj))
public_key = bytes.fromhex(
        '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')
print(obj.ec_pubkey_parse(public_key))
