## libsecp256k1-py: Python implementation of bitcoin core libsec256k1.

#THIS IS A SUPER WIP

### Setup

#### Install
$ git clone https://github.com/rrybarczyk/pysecp256k1.git
$ cd pysecp256k1
$ pipenv install

#### Build

Clone the bitcoin-core [libsecp256k1 repo](https://github.com/bitcoin-core/secp256k1.git) into the top level directory of this project

```
$ git clone https://github.com/bitcoin-core/secp256k1.git
```

Follow the bitcoin-core libsecp256k1 build steps:

```
$ ./autogen.sh
$ ./configure
$ make
$ ./tests
```

The directory structure should look like:

```
|-- pysecp256k1
|   |-- __init__.py
|   |-- secp256k1_build
|   |   |-- build.py
|   |   |-- secp256k1_headers
|   |   |   |--secp256k1.h
|   |-- examples
|   |   |-- ex_context.py
|   |__ tests
|      |__ test_context.py
|
|-- secp256k1 (bitcoin-core secp256k1 cloned repo)
|   |__.libs
|      |__ libsecp256k1.dylib (for Unix)
|-- other stuff that does not matter to getting this working and i dont want to type rn
```

Build the python bindings:

```
$ pipenv run python pysecp256k1/secp256k1_build/build.py
```

Now you should have the following files at the top level of the directory:

```
- _secp256k1.c
- _secp256k1.o
- _secp256k1.cpython-37m-darwin.so
```

Run the example file

```
$ pipenv run python ./pysecp256k1/examples/ex_content.py
```

Run the test (currenly no tests)

```
$ pipenv run pytest
```
