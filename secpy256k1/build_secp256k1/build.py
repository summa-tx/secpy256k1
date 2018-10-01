import os
from cffi import FFI

ffibuilder = FFI()
dir_path = os.path.dirname(os.path.realpath(__file__))

secp256k1_header = []
secp256k1_header.append(
    os.path.join(dir_path, 'secp256k1_headers/secp256k1_cdef.h'))
secp256k1_header.append(
    os.path.join(dir_path, 'secp256k1_headers/secp256k1_ecdh_cdef.h'))

for header in secp256k1_header:
    with open(header, 'rt') as h:
        ffibuilder.cdef(h.read())

ffibuilder.set_source(
    "_secpy256k1",  # This enters the namespace automatically.
    """
    #include "secp256k1.h"
    #include "secp256k1_ecdh.h"
    """,
    include_dirs=['./secp256k1/include'],  # secp256k1 install loc
    library_dirs=['./secp256k1/.libs'],
    libraries=['secp256k1'])

ffibuilder.compile(verbose=True)
