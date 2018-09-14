import _secp256k1
import pysecp256k1

obj = pysecp256k1.Context(_secp256k1.lib.SECP256K1_CONTEXT_NONE)
print(obj)
print(obj.context)
