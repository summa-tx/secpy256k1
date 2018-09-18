from pysecp256k1 import utils
from _secp256k1 import lib, ffi

CONTEXT_FLAGS = [
    lib.SECP256K1_CONTEXT_VERIFY,
    lib.SECP256K1_CONTEXT_SIGN,
    lib.SECP256K1_CONTEXT_NONE
]


def context_create(flags):
    '''Create a secp256k1 context object.
    Args:
        flag    (CONTEXT_FLAG):         which parts of the context to
                                        initialize
    Returns:
        ctx     (secp256k1_context):    a newly created context object
    '''
    # Validate context flags
    if flags not in CONTEXT_FLAGS:
        raise TypeError('Invalid context flag.')

    # Create context
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
    utils.validate_context(ctx)

    # Clone context
    return lib.secp256k1_context_clone(ctx)


def context_destroy(ctx):
    '''Destroy a secp256k1 context object.
    This context pointer may not be used afterwards.
    Args:
        ctx     (secp256k1_context):    an existing conect to destroy (cannot
                                        be NULL)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Destroy context
    lib.secp256k1_context_destroy(ctx)


def ec_pubkey_parse(ctx, input):
    '''Parse a variable-length public key into the pubkey object.
    This function supports parsing compressed (33 bytes, header byte 0x02 or
    0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes,
    header byte 0x06 or 0x07) format public keys.
    Args:
        ctx     (secp256k1_context*):       secp256k1 context object
        input   (bytes):                    pointer to a serialized public key
    Returns:
                (int, secp256k1_pubkey*):   (1 if the public key was fully
                                            valid. 0 if the public key could
                                            not be parsed or is invalid,
                                            pointer to a secp256k1_pubkey
                                            containing an initialized public
                                            key)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate input
    utils.validate_public_key_ser(input)

    # Length of the array pointed to by input
    inputlen = len(input)

    # Pointer to a pubkey object. If 1 is returned, it is set to a parsed
    # version of input. If not, its value is undefined.
    pubkey = ffi.new('secp256k1_pubkey *')

    return (lib.secp256k1_ec_pubkey_parse(ctx, pubkey, input, inputlen),
            pubkey)


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
        output  (ctype 'char[33]'):     a pointer to a 65-byte (if
                                        compressed==0) or 33-byte (if
                                        compressed==1) byte array to place the
                                        serialized key in
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate public key
    utils.validate_public_key(pubkey)

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
        ctx     (secp256k1_context*):           a secp256k1 context object,
                                                initialized for verification
        sig     (secp256k1_ecdsa_signature*):   the signature being verified
                                                (cannot be NULL)
        msg32   (bytes):                        the 32-byte message hash being
                                                verified (cannot be NULL)
        pubkey  (secp256k1_pubkey*):            pointer to an initialized
                                                public key to verify with
                                                (cannot be NULL)
    Returns:
                (int):                          1: correct signature
                                                0: incorrect or unparseable
                                                signature
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate pubkey
    utils.validate_public_key(pubkey)

    # Validate sig
    utils.validate_signature(sig)

    # Validate msg32
    utils.validate_msg32_ser(msg32)

    return lib.secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey)


def ecdsa_signature_normalize(ctx, sigout, sigin):
    pass


def ecdsa_sign(ctx, msg32, seckey, noncefp, ndata):
    '''Create an ECDSA signature.
    The created signature is always in lower-S form. See
    secp256k1_ecdsa_signature_normalize for more details.
    Args:
        ctx     (secp256k1_context*):       a secp256k1 context object,
                                            initialized for signing
        msg32   (bytes):                    the 32-byte message hash being
                                            signed (cannot be NULL)
        seckey  (bytes):                    pointer to a 32-byte secret key
                                            (cannot be NULL)
        noncefp (secp256k1_nonce_function): pointer to a nonce generation
                                            function. If NULL,
                                            secp256k1_nonce_function_default
                                            is used
        ndata   (void*):                    pointer to arbitrary data used by
                                            the nonce generation function (can
                                            be NULL)
    Returns:
        sig (secp256k1_ecdsa_signature*):   pointer to an array where the
                                            signature will be placed (cannot be
                                            NULL)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate msg32
    utils.validate_msg32_ser(msg32)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    # Validate noncefp
    utils.validate_noncefp(noncefp)

    # Validate ndata
    utils.validate_ndata(ndata)

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
    '''Tweak a private key by adding tweak to it.
    Args:
        ctx     (secp256k1_context*):   pointer to a context object (cannot be
                                        NULL).
        seckey  (bytes):                a 32-byte private key
        tweak   (bytes):                a 32-byte tweak
    Returns:
                (int, bytes):           (0 if the tweak was out of range
                                        (change of around 1 in 2^128 for
                                        uniformly random 32-byte arrays), or if
                                        the resulting private key would be
                                        invalid (only when the tweak is the
                                        complement of the corresponding private
                                        key). 1 otherwise, a pointer to a
                                        secp256k1_pubkey containing tweaked
                                        public key,
                                        a 32-byte private key)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    # Validate tweak
    utils.validate_tweak_ser(tweak)

    return (lib.secp256k1_ec_privkey_tweak_add(ctx, seckey, tweak), seckey)


def ec_pubkey_tweak_add(ctx, pubkey, tweak):
    ''' Tweak a public key by adding tweak times the generator to it.
    Args:
        ctx     (secp256k1_context):        a secp256k1 context object
        pubkey  (secp256k1_pubkey):         a pointer to a secp256k1_pubkey
                                            containing an initialized public
                                            key
        tweak   (bytes):                    a 32-byte tweak
    Returns:
                (int, secp256k1_pubkey*):   (0 if the tweak was out of range
                                            (change of around 1 in 2^128 for
                                            uniformly random 32-byte arrays),
                                            or if the resulting public key
                                            would be invalid (only when the
                                            tweak is the complement of the
                                            corresponding private key). 1
                                            otherwise,
                                            a pointer to a secp256k1_pubkey
                                            containing tweaked public key)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate public key
    utils.validate_public_key(pubkey)

    # Validate tweak
    utils.validate_tweak_ser(tweak)

    return (lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak), pubkey)


def ec_privkey_tweak_mul(ctx, seckey, tweak):
    pass


def ec_pubkey_tweak_mul(ctx, pubkey, tweak):
    pass


def context_randomize(ctx, seed32):
    pass


def ec_pubkey_combine(ctx, out, ins):
    pass
