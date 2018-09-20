## pysecp256k1: Python bindings for bitcoin core libsecp256k1. SUPER WIP.

### Setup and Build

```
$ git clone git@github.com:rrybarczyk/pysecp256k1.git
$ cd ./pysecp256k1
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
$ sudo make install ##for OS X
```

Build `_secp256k1` bindings.

```
$ pipenv run python ./pysecp256k1/build_secp256k1/build.py
```

The `_secp256k1` bindings are `_secp256k1.o`, `_secp256k1.c`, and `_sec256k1.cypython-37m-darwin.so` and should be located at the top level directory after running the `build.py` script.

Test.

```
$ pipenv run pytest
```

### Example File
Run the example file

```
$ pipenv run python ./pysecp256k1/examples/ex_script.py
```
