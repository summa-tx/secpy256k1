from cffi import FFI

ffi = FFI()

ffi.cdef("""
#define SECP256K1_CONTEXT_VERIFY ...
#define SECP256K1_CONTEXT_SIGN ...
#define SECP256K1_CONTEXT_NONE ...
typedef struct secp256k1_context_struct secp256k1_context;
typedef struct { unsigned char data[64]; } secp256k1_pubkey;
secp256k1_context* secp256k1_context_create(unsigned int flags);
void secp256k1_context_destroy(secp256k1_context* ctx);
int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char *input,
    size_t inputlen);
""")

ffi.set_source(
        "_secp256k1",
        """
        #include <secp256k1.h>
        """,
        library_dirs=['secp256k1/.libs'],
        libraries=['secp256k1'])

if __name__ == "__main__":
    ffi.compile(verbose=True)
