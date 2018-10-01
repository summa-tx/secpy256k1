import os
import pysecp256k1
pubkey = bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')   # noqa: E501
uncomp_pubkey = bytes.fromhex('0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8')    # noqa: E501
tweak = bytes.fromhex('aca0338ffd29daeb82021b179348db68ad0740d66698264d2e69e1ae9ab007f1')  # noqa: E501

# Set flag
flags = pysecp256k1.lib.SECP256K1_CONTEXT_VERIFY
#  flags = pysecp256k1.lib.SECP256K1_CONTEXT_SIGN
#  flags = pysecp256k1.lib.SECP256K1_CONTEXT_NONE

# Create context from flag
secp256k1_ctx = pysecp256k1.context_create(flags)
print(secp256k1_ctx)
print(type(secp256k1_ctx))

# Clone context
secp256k1_ctx_clone = pysecp256k1.context_clone(secp256k1_ctx)

# Destroy context clone
pysecp256k1.context_destroy(secp256k1_ctx_clone)

# Create secp256k1_pubkey
func_ret, secp256k1_pubkey = pysecp256k1.ec_pubkey_parse(
    ctx=secp256k1_ctx,
    input=pubkey)

# Verify pubkey could be parse and is valid
if func_ret == 0:
    print('ec_pubkey_parse could not be parsed or is invalid')

# Set pubkey compression flag
compression_flag = pysecp256k1.lib.SECP256K1_EC_COMPRESSED

# Serialize secp256k1_pubkey into byte string
func_ret, output, output_len = pysecp256k1.ec_pubkey_serialize(
    ctx=secp256k1_ctx,
    pubkey=secp256k1_pubkey,
    flags=compression_flag)

# Retrieve buffer reference to the serialized public key (output)
pubkey_ser = bytes(pysecp256k1.ffi.buffer(output))

if (pubkey_ser != pubkey):
    print('public key is not properly serialized.')

# Destroy context
pysecp256k1.context_destroy(secp256k1_ctx)

# Signing 
# Set SIGN context flag
flags = pysecp256k1.lib.SECP256K1_CONTEXT_SIGN

# Create SIGN context
secp256k1_ctx = pysecp256k1.context_create(flags)
print(dir(pysecp256k1.lib))
hh = '\x00'
print(hh)
#  gg = bytearray('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42\x52\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\xef\xa1\x7b\x77\x61\xe1\xe4\x27\x06\x98\x9f\xb4\x83\xb8\xd2\xd4\x9b\xf7\x8f\xae\x98\x03\xf0\x99\xb8\x34\xed\xeb\x00')
gg = b'\x7a\xe9\x6a\x2b\x65\x7c\x07\x10\x6e\x64\x47\x9e\xac\x34\x34\xe9\x9c\xf0\x49\x75\x12\xf5\x89\x95\xc1\x39\x6c\x28\x71\x95\x01\xee\x42\x18\xf2\x0a\xe6\xc6\x46\xb3\x63\xdb\x68\x60\x58\x22\xfb\x14\x26\x4c\xa8\xd2\x58\x7f\xdd\x6f\xbc\x75\x0d\x58\x7e\x76\xa7\xee'
print(gg)
print()
print(gg.hex())
print()
print(len(gg))
pubkey = '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee'

