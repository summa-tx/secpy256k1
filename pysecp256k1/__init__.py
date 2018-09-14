import _secp256k1


class Context(object):
    def __init__(self, context_flag):
        self.context = self.secp256k1_context_create(context_flag)

    def __del__(self):
        self.secp256k1_context_destroy()
        self.context = None

    def secp256k1_context_create(self, context_flag):
        return _secp256k1.lib.secp256k1_context_create(context_flag)

    def secp256k1_context_destroy(self):
        return _secp256k1.lib.secp256k1_context_destroy(self.context)
