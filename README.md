## secpy256k1: Python bindings for bitcoin core libsecp256k1. SUPER WIP. Only tested on Mac OS X.

### Quick Build
If you have `libsecp256k1.dylib` installed (/usr/local/lib/), and `cffi` >=1.11.5, in python 3.7:

```
$pip install secpy256k1
```

### Full Setup and Build

```
$ git clone git@github.com:rrybarczyk/secpy256k1.git
$ cd ./secpy256k1
$ pipenv install
```

Build submodule bitcoin-core [libsecp256k1 repo](https://github.com/bitcoin-core/secp256k1.git) library repo.

```
$ cd ./secp256k1
$ git submodule init
$ git submodule update
$ ./autogen.sh
$ ./configure --enable-module-ecdh --enable-module-recovery --enable-experimental
$ make
$ sudo make install ##NB! for OS X
```

Build `_secpy256k1` bindings.

```
$ pipenv run python ./secpy256k1/build_secp256k1/build.py
```

The `_secpy256k1` bindings are `_secpy256k1.o`, `_secpy256k1.c`, and `_pysec256k1.cypython-37m-darwin.so` and should be located at the top level directory after running the `build.py` script.

Test.

```
$ pipenv run pytest
```

### Example File
Run the example file

```
$ pipenv run python ./secpy256k1/examples/ex_script.py
```
