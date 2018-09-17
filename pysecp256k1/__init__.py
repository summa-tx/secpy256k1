from _secp256k1 import lib, ffi


def ctx_create(ctx):
    return lib.secp256k1_context_create(ctx)


def ctx_destroy(ctx):
    return lib.secp256k1_context_destroy(ctx)


def ec_pubkey_parse(ctx, pubkey):
    '''Parse a variable-length public key into the pubkey object.
    Args:
        ctx     (secp256k1_context):    a secp256k1 context object
        pubkey  (bytes):                serialized public key
    Returns:
        pubkey  (secp256k1_pubkey):     a pointer to a secp256k1_pubkey
                                        containing an initialized public key
    '''
    # TODO: Validate context
    # Validate public key
    if not isinstance(pubkey, bytes) or len(pubkey) not in [33, 65]:
        raise ValueError('Invalid pubkey. Must be 33- or 65-bytes.')

    inputlen = len(pubkey)
    input = pubkey
    pubkey = ffi.new('secp256k1_pubkey *')
    if lib.secp256k1_ec_pubkey_parse(ctx, pubkey, input, inputlen):
        return pubkey
    else:
        ValueError('Public key could not be parsed or is invalid.')


def ec_pubkey_serialize(ctx, pubkey, flags):
    '''Serialize a pubkey object into a serialized byte sequence.
    Args:
        ctx     (secp256k1_context):    a secp256k1 context object
        pubkey  (secp256k1_pubkey):     a pointer to a secp256k1_pubkey
                                        containing an initialized public key
        flags   (int):                  SECP256K1_EC_COMPRESSED if
                                        serialization should be in compressed
                                        format, otherwise
                                        SECP256K1_EC_UNCOMPRESSED
    Returns:
        pubkey  (bytes):                serialized public key
    '''
    # TODO: Validate context
    # TODO: Validate public key
    # Validate flags
    if flags is lib.SECP256K1_EC_COMPRESSED:
        publen = 33
    elif flags is lib.SECP256K1_EC_UNCOMPRESSED:
        publen = 65
    else:
        raise ValueError('Invalid serialized compression format flag.')

    # Pointer to a 33- or 65-byte array to place the serialized key in
    output = ffi.new('char [%d]' % publen)

    # Pointer to an integer which is initially set to the size of the output,
    # and is overwritten with the written size
    outputlen = ffi.new('size_t *', publen)

    if lib.secp256k1_ec_pubkey_serialize(
            ctx, output, outputlen, pubkey, flags):

        # Buffer object referencing cdata pointer -> bytes
        return bytes(ffi.buffer(output, publen))


def ec_privkey_tweak_add(ctx, seckey, tweak):
    pass
    #  return lib.secp256k1_ec_privkey_tweak_add(ctx, seckey, tweak)


def ec_pubkey_tweak_add(ctx, pubkey, tweak):
    ''' Tweak a public key by adding tweak times the generator to it.
    Args:
        ctx     (secp256k1_context):    a secp256k1 context object
        pubkey  (secp256k1_pubkey):     a pointer to a secp256k1_pubkey
                                        containing an initialized public key
        tweak   (bytes):                32-byte tweak
    Returns:
        pubkey  (secp256k1_pubkey):     a pointer to a secp256k1_pubkey
                                        containing tweaked public key
    '''
    pass
    #  # TODO: Validate context
    #  # TODO: Validate public key
    #
    #  #  # Validate tweak
    #  #  if not isinstance(tweak, bytes) or len(tweak) != 32:
    #  #      raise ValueError('Invalid tweak. Must be 32-bytes.')
    #
    #  pubkey = ffi.new('secp256k1_pubkey *')
    #  if lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak):
    #      return pubkey
