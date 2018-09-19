import os
from cffi import FFI

ffibuilder = FFI()
dir_path = os.path.dirname(os.path.realpath(__file__))
secp256k1_header = os.path.join(dir_path, 'secp256k1_headers/secp256k1.h')

with open(secp256k1_header, 'rt') as h:
    ffibuilder.cdef(h.read())

ffibuilder.set_source(
        "_secp256k1",
        """
        #include <secp256k1.h>
        """,
        library_dirs=['secp256k1/.libs'],
        libraries=['secp256k1'])

ffibuilder.compile(verbose=True)
