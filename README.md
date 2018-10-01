# riemann-secp256k1
NOTE: THIS LIBRARY HAS ONLY BEEN TESTED ON MACOSX. AND IT HAS BEEN BARELY TESTED REALLY AT ALL.

This library is designed to directly mimic the functionality of bitcoin-cores's [libsecp256k1](https://github.com/bitcoin-core/secp256k1.git) library. It is designed to be a lower level wrapper around libsecp256k1 so it can be be easily integrated into other projects.

The CFFI library is used to create the Python bindings.


## Quick Install (MacOSX ONLY)

From [libsecp256k1](https://github.com/bitcoin-core/secp256k1.git), make sure `libsecp256k1.dylib` is installed in `/usr/local/lib/` via:

```
$pip install riemann-secp256k1
$ ./autogen.sh
$ ./configure --enable-module-ecdh --enable-module-recovery --enable-experimental
$ make
$ sudo make install
```

Install from PyPi:

```
$ pip install riemann-secp256k1
```

Import the `riemann_secp256k1` package at the top of your python script:

`import riemann_secp256k1`


## Development

```
$ git clone git@github.com:summa-tx/riemann-secp256k1.git
$ cd ./riemann-secp256k1
$ pipenv install
```

Build submodule bitcoin-core [libsecp256k1 repo](https://github.com/bitcoin-core/secp256k1.git) library repo:

```
$ cd ./secp256k1
$ git submodule init
$ git submodule update
$ ./autogen.sh
$ ./configure --enable-module-ecdh --enable-module-recovery --enable-experimental
$ make
$ sudo make install
```

Build `_riemann_secp256k1` bindings.

```
$ pipenv run python ./riemann_secp256k1/build_secp256k1/build.py
```

The `_riemann_secp256k1` bindings are `_riemann_secp256k1.o`, `_riemann_secp256k1.c`, and `_pysec256k1.cypython-37m-darwin.so` and should be located at the top level directory after running the `build.py` script.

Install dependencies and build `_riemann_secp256k1` bindings:

```
$ pipenv install
```

### Test

The tests are currently lacking. Intend to use test vectors from the libsecp256k1 library.

```
$ pipenv run pytest
```

### Example File

```
$ pipenv run python ./riemann_secp256k1/examples/ex_script.py
```

## API
### Context

Barring the `context_create` function, the first argument to each function is a `secp256k1_context` object which is set with one of the three following context flags:
1. `SECP256K1_CONTEXT_VERIFY`
1. `SECP256K1_CONTEXT_SIGN`
1. `SECP256K1_CONTEXT_NONE`

Set the context flag:
```
# Set verify flag
flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_VERIFY

# Set sign flag
flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_SIGN

# Set none flag
flags = riemann_secp256k1.lib.SECP256K1_CONTEXT_NONE
```

Create a pointer to a `secp256k1_context` object from the context flag:
```
secp256k1_ctx = riemann_secp256k1.context_create(flags)
```

Clone a pointer to a `secp256k1_context` object:
```
secp256k1_ctx_clone = riemann_secp256k1.context_clone(secp256k1_ctx)
```

Destroy a pointer to a `secp256k1_context` object:
```
secp256k1_ctx_destroy = riemann_secp256k1.context_destroy(secp256k1_ctx)
```

Update the context randomization to protect against side-channel leakage:
```
import os
seed32 = os.urandom(32)
func_res = riemann_secp256k1.context_randomize(ctx=secp256k1_ctx, seed32)
```

### Pubkey

Public key flags:
1. `SECP256K1_COMPRESSED` - flags a 33-byte compressed pubkey
1. `SECP256K1_UNCOMPRESSED` - flags a 65-byte uncompressed pubkey

Set pubkey compression flag:
```
# Set compressed pubkey flag
pubkey = bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')
compression_flag = riemann_secp256k1.lib.SECP256K1_COMPRESSED

# Set uncompressed pubkey flag
pubkey = bytes.fromhex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
compression_flag = riemann_secp256k1.lib.SECP256K1_UNCOMPRESSED
```

Create a pointer to a `secp256k1_pubkey` object from a compressed or uncompressed serialized pubkey byte string:
```
pk_valid, secp256k1_pk = riemann_secp256k1.ec_pubkey_parse(secp256k1_ctx, pubkey)
```

Serialize `secp256k1_pubkey` object into a serialized pubkey byte string:
```
# Set compression flag
compression_flag = riemann_secp256k1.lib.SECP256k1_EC_COMPRESSED

pubkey_valid, pubkey, pubkey_len = riemann_secp256k1.ec_pubkey_serialize(secp256k1_ctx, secp256k1_pk, compression_flag
```

Create a pointer to a `secp26k1_pubkey` object containing the corresponding public key to a given private key:
```
import os
priv_key = os.urandom(32)
func_ret, secp256k1_pubkey = riemann_secp256k1.ec_pubkey_create(ctx=secp256k1_ctx, seckey=priv_key)
```

Negate public key:
```
TODO -> ec_pubkey_negate(ctx=secp256k1_ctx, pubkey=secp256k1_pubkey)
```

Negate private key:
```
TODO -> ec_privkey_negate(ctx=secp256k1_ctx, seckey=priv_key)
```

Add a number of public keys together:
```
pubkeys = [pubkey1, pubkey2, pubkey3]
func_ret, secp256k1_pubkey = riemann_secp256k1.ec_pubkey_combine(ctx=secp256k1_ctx, pubkeys=pubkeys)
```

### Signing (TODO)

1. ecdsa_signature_parse_compact
1. ecdsa_signature_parse_der
1. ecdsa_signature_serialize_der
1. ecdsa_signature_serialize_compact
1. ecdsa_verify
1. ecdsa_signature_normalize
1. ecdsa_sign
1. ec_seckey_verify


### Tweaking

Define a tweak:
```
import os
tweak = os.urandom(32)
```

Tweak a secp256k1_pubkey object by adding `tweak` times the generator to it:
```
func_ret, secp256k1_pubkey_tweaked = riemann_secp256k1.ec_pubkey_tweak_add(ctx=secp256k1_ctx, pubkey=secp256k1_pubkey, tweak=tweak)
```

Tweak a private key by adding `tweak` times the generator to it:
```
func_ret, priv_key_tweaked = riemann_secp256k1.ec_privkey_tweak_add(ctx=secp256k1_ctx, seckey=priv_key, tweak=tweak)
```

Tweak a secp256k1_pubkey object by multiplying `tweak` by a tweak value:
```
func_ret, secp256k1_pubkey_tweaked = riemann_secp256k1.ec_pubkey_tweak_mul(ctx=secp256k1_ctx, pubkey=secp256k1_pubkey, tweak=tweak)
```

Tweak a private key by multiplying `tweak` it by a tweak value:
```
func_ret, priv_key_tweaked = riemann_secp256k1.ec_privkey_tweak_mul(ctx=secp256k1_ctx, seckey=priv_key, tweak=tweak)
```

### EC Diffie-Hellman

Compute an ECDH secret in constant time:
```
func_ret, ecdh_secret = riemann_secp256k1.ecdh(ctx=secp256k1_ctx, pubkey=secp256k1_pubkey, privkey=priv_key)
```


