import _secp256k1


class Context(object):
    def __init__(self, context_flag):
        self.context = _secp256k1.lib.secp256k1_context_create(context_flag)

    def __del__(self):
        _secp256k1.lib.secp256k1_context_destroy(self.context)
        self.context = None


class PublicKey(Context):

    def __init__(self, context_flag, public_key):
        Context.__init__(self)
        self.public_key = public_key
