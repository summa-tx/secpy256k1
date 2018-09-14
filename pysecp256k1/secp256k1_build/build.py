import pkg_resources
from cffi import FFI

ffibuilder = FFI()

secp256k1_header = pkg_resources.resource_string(
    'pysecp256k1',
    'secp256k1_build/secp256k1_headers/secp256k1.h').decode('utf-8')

ffibuilder.cdef(secp256k1_header)

ffibuilder.set_source(
        "_secp256k1",
        """
        #include <secp256k1.h>
        """,
        library_dirs=['secp256k1/.libs'],
        libraries=['secp256k1'])

ffibuilder.compile(verbose=True)
