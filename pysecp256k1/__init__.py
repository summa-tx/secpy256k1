from _secp256k1 import lib, ffi


class Context(object):
    def __init__(self, context_flag):
        self.context = lib.secp256k1_context_create(context_flag)

    def __del__(self):
        lib.secp256k1_context_destroy(self.context)
        self.context = None

    def ec_pubkey_parse(self, public_key):
        '''Parse a variable-length public key into the pubkey object.
        Args:
            public_key  (bytes)
        Returns:
            1 if the public key was fully valid
            0 if the public key could not be parse or is invalid
        '''
        return lib.secp256k1_ec_pubkey_parse(
                self.context,
                ffi.new('secp256k1_pubkey*'),
                public_key,
                len(public_key))
