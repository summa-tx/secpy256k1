## pysecp256k1: Python bindings for bitcoin core libsec256k1.

### Setup and Build

```
$ git clone git@github.com:rrybarczyk/pysecp256k1.git
$ cd ./pysecp256k1
$ pipenv install
$ pipenv run python ./pysecp256k1/build_secp256k1/build.py
$ pipenv pytest
```

Building requires that the bitcoin-core [libsecp256k1 repo](https://github.com/bitcoin-core/secp256k1.git) library is compiled and the resulting `libsecp256k1.dylib` (MacOSX), `libsecp256k1.so` (Linux), or `libsecp256k1.ddl` (Windows) file is installed in the `/usr/local/lib` directory.

The `_secp256k1` bindings are `_secp256k1.o`, `_secp256k1.c`, and `_sec256k1.cypython-37m-darwin.so` and should be located at the top level directory after running the `build.py` script.

### Example File
Run the example file

```
$ pipenv run python ./pysecp256k1/examples/ex_content.py
```

