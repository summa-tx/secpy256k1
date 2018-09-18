from _secp256k1 import lib, ffi

CONTEXT_FLAGS = [
    lib.SECP256K1_CONTEXT_VERIFY,
    lib.SECP256K1_CONTEXT_SIGN,
    lib.SECP256K1_CONTEXT_NONE
]


def context_create(flags):
    '''Create a secp256k1 context object.
    Args:
        flags   (CONTEXT_FLAG):         which parts of the context to
                                        initialize
    Returns:
        ctx     (secp256k1_context):    a newly created context object
    '''
    # Validate context flags
    if flags not in CONTEXT_FLAGS:
        raise TypeError('Invalid context flag.')

    return lib.secp256k1_context_create(flags)


def context_clone(ctx):
    '''Copies a secp256k1 context object.
    Args:
        ctx     (secp256k1_context):    an existing context to copy (cannot be
                                        NULL)
    Returns:
        ctx     (secp256k1_context):    a newly created context object
    '''
    # Validate context
    validate_context(ctx)

    return lib.secp256k1_context_clone(ctx)


def context_destroy(ctx):
    '''Destroy a secp256k1 context object.
    This context pointer may not be used afterwards.
    Args:
        ctx     (secp256k1_context):    an existing conect to destroy (cannot
                                        be NULL)
    '''
    # Validate context
    validate_context(ctx)

    lib.secp256k1_context_destroy(ctx)


def ec_pubkey_parse(ctx, input):
    '''Parse a variable-length public key into the pubkey object.
    This function supports parsing compressed (33 bytes, header byte 0x02 or
    0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes,
    header byte 0x06 or 0x07) format public keys.
    Args:
        ctx     (secp256k1_context):    secp256k1 context object
        input   (bytes):                pointer to a serialized public key
    Returns:
        pubkey  (secp256k1_pubkey):     pointer to a secp256k1_pubkey
                                        containing an initialized public key
    '''
    # Validate context
    validate_context(ctx)

    # Validate input
    if not isinstance(input, bytes) or len(input) not in [33, 65]:
        raise ValueError('Invalid pubkey. Must be 33- or 65-bytes.')

    # Length of the array pointed to by input
    inputlen = len(input)

    # Pointer to a pubkey object. If 1 is returned, it is set to a parsed
    # version of input. If not, its value is undefined.
    pubkey = ffi.new('secp256k1_pubkey *')

    # Returns: 1 if the public key was fully valid.
    #          0 if the public key could not be parsed or is invalid.
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
        output (ctype 'char[33]'):      a pointer to a 65-byte (if
                                        compressed==0) or 33-byte (if
                                        compressed==1) byte array to place the
                                        serialized key in
    '''
    # Validate context
    validate_context(ctx)

    # Validate public key
    validate_public_key(pubkey)

    # Validate flags
    if flags is lib.SECP256K1_EC_COMPRESSED:
        publen = 33
    elif flags is lib.SECP256K1_EC_UNCOMPRESSED:
        publen = 65
    else:
        raise ValueError('Invalid serialized compression format flag.')

    # Pointer to a 33- or 65-byte array to place the serialized key in
    output = ffi.new('char[]', publen)

    # Pointer to an integer which is initially set to the size of the output,
    # and is overwritten with the written size
    outputlen = ffi.new('size_t *', publen)

    if lib.secp256k1_ec_pubkey_serialize(
            ctx, output, outputlen, pubkey, flags):
        return output


def ecdsa_signature_parse_compact(ctx, sig, input64):
    pass


def ecdsa_signature_parse_der(ctx, sig, input, inputlen):
    pass


def ecdsa_signature_serialize_der(ctx, output, outputlen, sig):
    pass


def ecdsa_signature_serialize_compact(ctx, output64, sig):
    pass


def ecdsa_verify(ctx, sig, msg32, pubkey):
    '''Verify an ECDSA signature.
    To avoid accepting malleable signatures, only ECDSA signatures in lower-S
    form are accepted.
    If you need to accept ECDSA signatures from sources that do not obey this
    rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
    validation, but be aware that doing so results in malleable signatures.
    For details, see the comments for that function.
    Args:
        ctx (secp256k1_context*):           a secp256k1 context object,
                                            initialized for verification
        sig (secp256k1_ecdsa_signature*):   the signature being verified
                                            (cannot be NULL)
        msg32 (str):                        the 32-byte message hash being
                                            verified (cannot be NULL)
        pubkey (secp256k1_pubkey*):         pointer to an initialized public
                                            key to verify with (cannot be NULL)
    Returns: 1: correct signature
             0: incorrect or unparseable signature
    '''
    # Validate context
    validate_context(ctx)

    # Validate pubkey
    validate_public_key(pubkey)

    # Validate sig
    validate_signature(sig)

    # Validate msg
    if not isinstance(msg32, bytes) or len(msg32) != 32:
        raise ValueError('Invalid msg32. Must be 32-bytes.')

    return lib.secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey)


def ecdsa_signature_normalize(ctx, sigout, sigin):
    pass


def ecdsa_sign(ctx, msg32, seckey, noncefp, ndata):
    '''Create an ECDSA signature.
    The created signature is always in lower-S form. See
    secp256k1_ecdsa_signature_normalize for more details.
    Args:
        ctx (secp256k1_context*):           a secp256k1 context object,
                                            initialized for signing
        msg32 (str):                        the 32-byte message hash being
                                            signed (cannot be NULL)
        seckey (bytes):                     pointer to a 32-byte secret key
                                            (cannot be NULL)
        noncefp (secp256k1_nonce_function): pointer to a nonce generation
                                            function. If NULL,
                                            secp256k1_nonce_function_default
                                            is used
        ndata (void*):                      pointer to arbitrary data used by
                                            the nonce generation function (can
                                            be NULL)
    Returns:
        sig (secp256k1_ecdsa_signature*):   pointer to an array where the
                                            signature will be placed (cannot be
                                            NULL)
    '''

    # Validate context
    validate_context(ctx)

    # Validate msg32
    if not isinstance(msg32, bytes) or len(msg32) != 32:
        raise ValueError('Invalid msg32. Must be 32-bytes.')

    # Validate secret key
    if not isinstance(seckey, bytes) or len(seckey) != 32:
        raise ValueError('Invalid msg. Must be 32-bytes.')

    # Validate noncefp
    validate_noncefp(noncefp)

    # Validate ndata
    if ndata is not ffi.NULL:
        print('do more ndata validation')
        raise TypeError('Invalid ndata. Must be NULL.')

    sig = ffi.new('secp256k1_ecdsa_signature *')

    #  Returns: 1: signature created
    #           0: the nonce generation function failed, or the private key was
    #              invalid.
    if lib.secp256k1_ecdsa_sign(ctx, sig, msg32, seckey, noncefp, ndata):
        return sig


def ec_seckey_verify(ctx, seckey):
    pass


def ec_pubkey_create(ctx, pubkey, seckey):
    pass


def ec_privkey_negate(ctx, seckey):
    pass


def ec_pubkey_negate(ctx, pubkey):
    pass


def ec_privkey_tweak_add(ctx, seckey, tweak):
    pass


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
    # Validate context
    validate_context(ctx)

    # Validate public key
    validate_public_key(pubkey)

    # Validate tweak
    if not isinstance(tweak, bytes) or len(tweak) != 32:
        raise ValueError('Invalid tweak. Must be 32-bytes.')

    if lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak):
        return pubkey


def ec_privkey_tweak_mul(ctx, seckey, tweak):
    pass


def ec_pubkey_tweak_mul(ctx, pubkey, tweak):
    pass


def context_randomize(ctx, seed32):
    pass


def ec_pubkey_combine(ctx, out, ins):
    pass


def validate_context(ctx):
    '''Checks that context is a valid secp256k1_context struct pointer.
    Args:
        ctx     (secp256k1_context):    a secp256k1 context object
    Returns:
                (True):                 if ctx is valid, otherwise error
    '''
    return _validate_cdata_type(
            ctx,
            'struct secp256k1_context_struct *',
            'Invalid context. Must be secp256k1_context_struct pointer.')


def validate_public_key(pubkey):
    '''Checks that pubkey is a valid secp256k1_pubkey pointer.
    Args:
        pubkey  (secp256k1_pubkey*):    pointer to secp256k1 context object
    Returns:
                (True):                 if pubkey is valid, otherwise error
    '''
    return _validate_cdata_type(
            pubkey,
            'secp256k1_pubkey *',
            'Invalid pubkey. Must be secp256k1_pubkey pointer.')


def validate_signature(sig):
    '''Checks that signature is a valid secp256k1_ecdsa_signature pointer.
    Args:
        sig (secp256k1_ecdsa_signature*):   pointer to secp256k1 ecdsa
                                            signature object
    Returns:
        (True):                             if sig is valid, otherwise error
    '''
    return _validate_cdata_type(
            sig,
            'secp256k1_ecdsa_signature *',
            'Invalid sig. Must be secp256k1_ecdsa_signature pointer.')


def validate_noncefp(noncefp):
    '''Checks that noncefpis a valid secp256k1_nonce_function pointer or NULL.
    Args:
        noncefp (secp256k1_nonce_function*):    pointer to secp256k1 nonce
                                                generation function or NULL
    Returns:
        (True):                                 if noncefp is valid, otherwise
                                                error
    '''
    if noncefp is ffi.NULL:
        return True

    return _validate_cdata_type(
            noncefp,
            'secp256k1_nonce_function *',
            'Invalid noncefp. Must be secp256k1_nonce_function pointer.')


def _validate_cdata_type(value, type_str, err_msg):
    '''Checks that value is a valid ffi CData type.
    Args:
        value   (ffi.CData):    a secp256k1 context object
    Returns:
                (True):         if value is valid, otherwise error
    '''
    if not isinstance(value, ffi.CData):
        raise TypeError(err_msg)

    elif ffi.typeof(value) is not ffi.typeof(type_str):
        raise TypeError(err_msg)

    return True
