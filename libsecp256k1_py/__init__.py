import _secp256k1


class Context:
    def __init__(self, context_flag):
        self.context = self.secp256k1_create_context(context_flag)

    def secp256k1_create_context(self, context_flag):
        return _secp256k1.lib.secp256k1_context_create(context_flag)
