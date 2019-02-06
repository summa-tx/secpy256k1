from secpy256k1 import utils
from _secpy256k1 import lib, ffi

CONTEXT_FLAGS = [
    lib.SECP256K1_CONTEXT_VERIFY,
    lib.SECP256K1_CONTEXT_SIGN,
    lib.SECP256K1_CONTEXT_NONE
]


def context_create(flags):
    '''Create a secp256k1 context object.
    Args:
        flag    (int):                  which parts of the context to
                                        initialize
    Returns:
        ctx     (secp256k1_context*):   a newly created context object
    '''
    # Validate context flags
    if flags not in CONTEXT_FLAGS:
        raise TypeError('Invalid context flag.')

    # Create context
    return lib.secp256k1_context_create(flags)


def context_clone(ctx):
    '''Copies a secp256k1 context object.
    Args:
        ctx     (secp256k1_context*):   an existing context to copy (cannot be
                                        NULL)
    Returns:
        ctx     (secp256k1_context*):   a newly created context object
    '''
    # Validate context
    utils.validate_context(ctx)

    # Clone context
    return lib.secp256k1_context_clone(ctx)


def context_destroy(ctx):
    '''Destroy a secp256k1 context object.
    This context pointer may not be used afterwards.
    Args:
        ctx     (secp256k1_context*):   an existing conect to destroy (cannot
                                        be NULL)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Destroy context
    lib.secp256k1_context_destroy(ctx)


def context_set_illegal_callback(ctx, fun, data):
    pass


def context_set_error_callback(ctx, fun, data):
    pass


def scratch_space_create(ctx, max_size):
    pass


def scratch_space_destroy(scratch):
    pass


def ec_pubkey_parse(ctx, ser_pub):
    '''Parse a variable-length public key into the pubkey object.
    This function supports parsing compressed (33 bytes, header byte 0x02 or
    0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes,
    header byte 0x06 or 0x07) format public keys.
    Args:
        ctx     (secp256k1_context*):   secp256k1 context object
        ser_pub   (bytes):                pointer to a serialized public key
    Returns:
        (int, secp256k1_pubkey*):       (1 if the public key was fully
                                        valid. 0 if the public key could
                                        not be parsed or is invalid,
                                        pointer to a secp256k1_pubkey
                                        containing an initialized public
                                        key)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate input
    utils.validate_public_key_ser(ser_pub)

    # Length of the array pointed to by input
    inputlen = len(ser_pub)

    # Pointer to a pubkey object. If 1 is returned, it is set to a parsed
    # version of input. If not, its value is undefined.
    pubkey = ffi.new('secp256k1_pubkey *')

    return (lib.secp256k1_ec_pubkey_parse(ctx, pubkey, ser_pub, inputlen),
            pubkey)


def ec_pubkey_serialize(ctx, pubkey, flags):
    '''Serialize a pubkey object into a serialized byte sequence.
    Args:
        ctx     (secp256k1_context*):       a secp256k1 context object
        pubkey  (secp256k1_pubkey*):        a pointer to a secp256k1_pubkey
                                            containing an initialized public
                                            key
        flags   (int):                      SECP256K1_EC_COMPRESSED if
                                            serialization should be in
                                            compressed format, otherwise
                                            SECP256K1_EC_UNCOMPRESSED
    Returns:
        (int, ctype 'char[33]', size_t*):   (1,
                                            a pointer to a 65-byte (if
                                            compressed==0) or 33-byte (if
                                            compressed==1) byte array to place
                                            the serialized key in,
                                            Pointer to an integer which is
                                            initially set to the size of the
                                            output, and is overwritten with the
                                            written size)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate public key
    utils.validate_public_key(pubkey)

    # Validate flags
    if flags == lib.SECP256K1_EC_COMPRESSED:
        publen = 33
    elif flags == lib.SECP256K1_EC_UNCOMPRESSED:
        publen = 65
    else:
        raise ValueError('Invalid serialized compression format flag.')

    # Pointer to a 33- or 65-byte array to place the serialized key in
    output = ffi.new('char[]', publen)

    # Pointer to an integer which is initially set to the size of the output,
    # and is overwritten with the written size
    outputlen = ffi.new('size_t *', publen)
    output_length = int(ffi.cast('uint32_t', outputlen[0]))

    return (lib.secp256k1_ec_pubkey_serialize(
        ctx, output, outputlen, pubkey, flags),
        output[0:output_length],
        outputlen)


def ecdsa_signature_parse_compact(ctx, input64):
    '''Parse an ECDSA signature in compact (64 bytes) format.

    The signature must consist of a 32-byte big endian R value, followed by a
    32-byte big endian S value. If R or S fall outside of [0..order-1], the
    encoding is invalid. R and S with value 0 are allowed in the encoding.

    After the call, sig will always be initialized. If parsing failed or R or
    S are zero, the resulting sig value is guaranteed to fail validation for
    any message and public key.

    Args:
        ctx     (secp256k1_context*):       a secp256k1 context object
        input64 (bytes):                    a pointer to the 64-byte array to
                                            parse
    Returns:
        (int, secp256k1_ecdsa_signature*):  (1 when the signature could be
                                            parsed, 0 otherwise,
                                            a pointer to a signature object)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Pointer to a signature object
    sig = ffi.new('secp256k1_ecdsa_signature *')

    # Parse an ECDSA signature in compact (64 bytes) format
    return (lib.secp256k1_ecdsa_signature_parse_compact(ctx, sig, input64),
            sig)


def ecdsa_signature_parse_der(ctx, ser_sig):
    '''Parse a DER ECDSA signature.

    This function will accept any valid DER encoded signature, even if the
    encoded numbers are out of range.

    After the call, sig will always be initialized. If parsing failed or the
    encoded numbers are out of range, signature validation with it is
    guaranteed to fail for every message and public key.

    Args:
        ctx     (secp256k1_context*):       a secp256k1 context object
        ser_sig   (bytes):                    a pointer to the signature to be
                                            parsed
    Returns:
        (int, secp256k1_ecdsa_signature*):  (1 when the signature could be
                                            parsed, 0 otherwise,
                                            a pointer to a signature object)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate signature
    utils.validate_signature_ser(ser_sig)

    # Length of the array pointed to be input
    inputlen = len(ser_sig)

    # Pointer to a signature object
    sig = ffi.new('secp256k1_ecdsa_signature *')

    # Parse a DER ECDSA signature
    return (
        lib.secp256k1_ecdsa_signature_parse_der(ctx, sig, ser_sig, inputlen),
        sig)


def ecdsa_signature_serialize_der(ctx, sig, outputlen=74):
    '''Serialize an ECDSA signature in DER format.
    Args:
        ctx         (secp256k1_context*):           a secp256k1 context object
        sig         (secp256k1_ecdsa_signature*):   a pointer to an initialized
                                                    signature object
        outputlen   (int):                          pointer to a length of
                                                    output
    Returns:
        (int, unsigned char[], size_t*):            (1 if enough space was
                                                    available to serialize, 0
                                                    otherwise, a pointer to an
                                                    array to store the DER
                                                    serialization, a pointer to
                                                    a length of the
                                                    serialization (even if 0
                                                    was returned))
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate signature
    utils.validate_signature(sig)

    # Pointer to an array to store the DER serialization
    output = ffi.new('unsigned char[]', outputlen)

    # Pointer to a length integer
    outputlen = ffi.new('size_t *', outputlen)

    res = lib.secp256k1_ecdsa_signature_serialize_der(
        ctx, output, outputlen, sig)

    output_length = int(ffi.cast('uint32_t', outputlen[0]))

    # Serialize an ECDSA signature in DER format
    return (res, output[0:output_length], outputlen)


def ecdsa_signature_serialize_compact(ctx, sig):
    '''Serialize an ECDSA signature in compact (64 byte) format.
    See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
    Args:
        ctx (secp256k1_context*):           a secp256k1 context object
        sig (secp256k1_ecdsa_signature*):   a pointer to an initialized
                                            signature object
    Returns:
        (int, unsigned char):               (1,
                                            a pointer to a 64-byte array to
                                            store the compact serialization)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate signature
    utils.validate_signature(sig)

    # Pointer to a 64-byte array to store the compact serialization
    output64 = ffi.new('unsigned char[]', 64)

    return (
        lib.secp256k1_ecdsa_signature_serialize_compact(ctx, output64, sig),
        output64)


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
    '''Convert a signature to a normalized lower-S form.

    With ECDSA a third-party can forge a second distinct signature of the same
    message, given a single initial signature, but without knowing the key.
    This is done by negating the S value modulo the order of the curve,
    'flipping' the sign of the random point R which is not included in the
    signature.

    Forgery of the same message isn't universally problematic, but in systems
    where message malleability or uniqueness of signatures is important this
    can cause issues. This forgery can be blocked by all verifiers forcing
    signers to use a normalized form.

    The lower-S form reduces the size of signatures slightly on average when
    variable length encodings (such as DER) are used and is cheap to verify,
    making it a good choice. Security of always using lower-S is assured
    because anyone can trivially modify a signature after the fact to enforce
    this property anyway.

    The lower S value is always between 0x1 and
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
    inclusive.

    No other forms of ECDSA malleability are known and none seem likely, but
    there is no formal proof that ECDSA, even with this additional restriction,
    is free of other malleability. Commonly used serialization schemes will
    also accept various non-unique encodings, so care should be taken when this
    property is required for an application.

    The secp256k1_ecdsa_sign function will by default create signatures in the
    lower-S form, and secp256k1_ecdsa_verify will not accept others. In case
    signatures come from a system that cannot enforce this property,
    secp256k1_ecdsa_signature_normalize must be called before verification.

    Args:
        ctx     (secp256k1_context*):           a secp256k1 context object
        sigin   (secp256k1_ecdsa_signature*):   a pointer to a signature to
                                                check/normalize (cannot be
                                                NULL, can be identical to
                                                sigout)
    Returns:
        (int, secp256k1_ecdsa_signature*):      (1 if sigin was not normalized,
                                                0 if it already was,
                                                a pointer to a signature to
                                                fill with the normalized form,
                                                or copy if the input was
                                                already normalized. (can be
                                                NULL if you're only interested
                                                in whether the input was
                                                already normalized).
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate sig
    utils.validate_signature(sigin)

    # Pointer to a signature to fill witht he normalized form, or copy if the
    # input was already normalized
    sigout = ffi.new('secp256k1_ecdsa_signature *')

    return (lib.secp256k1_ecdsa_signature_normalize(ctx, sigout, sigin),
            sigout)


def ecdsa_sign(
        ctx, msg32, seckey, noncefp=ffi.NULL, ndata=ffi.NULL):
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
        (int, secp256k1_ecdsa_signature*):  (1: signature created, 0: the nonce
                                            generation function failed, or the
                                            private key was invalid,
                                            pointer to an array where the
                                            signature will be placed (cannot be
                                            NULL))
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

    return (lib.secp256k1_ecdsa_sign(ctx, sig, msg32, seckey, noncefp, ndata),
            sig)


def ec_seckey_verify(ctx, seckey):
    '''Verify an ECDSA secret key.
    Args:
        ctx     (secp256k1_context*):   a secp256k1 context object (cannot be
                                        NULL)
        seckey  (bytes):                pointer to a 32-byte secret key (cannot
                                        NULL)
    Returns:
        (int):                          1 if secret key is valid, 0 if secret
                                        key is invalid
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    return lib.secp256k1_ec_seckey_verify(ctx, seckey)


def ec_pubkey_create(ctx, seckey):
    '''Compute the public key for a secret key.
    Args:
        ctx     (secp256k1_context*):   a secp256k1 context object, initialized
                                        for signing (cannot be NULL)
        seckey  (bytes):                pointer to a 32-byte private key
                                        (cannot be NULL)
    Returns:
        (int, secp256k1_pubkey):        (1 if secret was valid, public key
                                        stores, 0 if secret was invalid, try
                                        again,
                                        pointer to the created public key
                                        (cannot be NULL))
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    # Pointer to the created public key
    pubkey = ffi.new('secp256k1_pubkey *')

    # Compute the public key for a secret key
    return (lib.secp256k1_ec_pubkey_create(ctx, pubkey, seckey), pubkey)


def ec_privkey_negate(ctx, seckey):
    '''Negates a private key in place.
    Args:
        ctx     (secp256k1_context*):   a secp256k1 context object
        seckey  (bytes):                pointer to a 32-byte private key to be
                                        negated (cannot be NULL)
    Returns:
        (int, bytes):                   (1 always,
                                        pointer to the 32-byte private key to
                                        be negated (cannot be NULL))
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    # Negate a private key in place
    return (lib.secp256k1_ec_privkey_negate(ctx, seckey), seckey)


def ec_pubkey_negate(ctx, pubkey):
    '''Negates a public key in place.
    Args:
        ctx     (secp256k1_context*):   a secp256k1 context object
        pubkey  (secp256k1_pubkey*):    pointer to the public key to be negated
                                        (cannot be NULL)
    Returns:
        (int, secp256k1_pubkey*):       (1 always,
                                        pointer to the public key to be negated
                                        (cannot be NULL))
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate public key
    utils.validate_public_key(pubkey)

    return (lib.secp256k1_ec_pubkey_negate(ctx, pubkey), pubkey)


def ec_privkey_tweak_add(ctx, seckey, tweak):
    '''Tweak a private key by adding tweak to it.
    Args:
        ctx     (secp256k1_context*):   pointer to a context object (cannot be
                                        NULL).
        seckey  (bytes):                a 32-byte private key
        tweak   (bytes):                a 32-byte tweak
    Returns:
        (int, bytes):                   (0 if the tweak was out of range
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
        ctx     (secp256k1_context*):   pointer to a context object (cannot be
                                        NULL)
        pubkey  (secp256k1_pubkey*):    pointer to a public key object
        tweak   (bytes):                pointer to a 32-byte tweak
    Returns:
        (int, secp256k1_pubkey*):       (0 if the tweak was out of range
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
    '''Tweak a private key by multiplying it by a tweak.
    Args:
        ctx     (secp256k1_context*):   pointer to a context object (cannot be
                                        NULL)
        seckey  (bytes):                pointer to a 32-byte private key
        tweak   (bytes):                pointer to a 32-byte tweak
    Returns:
        (int, seckey):                  (0 if the tweak was out of range
                                        (chance of around 1 in 2^128 for
                                        uniformly random 32-byte arrays, or
                                        equal to zero. 1 otherwise,
                                        pointer to a 32-byte private key)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate secret key
    utils.validate_secret_key_ser(seckey)

    # Validate tweak
    utils.validate_tweak_ser(tweak)

    return (lib.secp256k1_ec_privkey_tweak_mul(ctx, seckey, tweak), seckey)


def ec_pubkey_tweak_mul(ctx, pubkey, tweak):
    '''Tweak a public key by multiplying it by a tweak value.
    Args:
        ctx     (secp256k1_context*):   pointer to a context object
                                        initialized for validation (cannot be
                                        NULL)
        pubkey  (secp2561_pubkey*):     pointer to a public key object
        tweak   (bytes):                pointer to a 32-byte tweak
    Returns:
        (int, secp256k1_pubkey*):       (0 if the tweak was out of range
                                        (chance of around 1 in 2^128 for
                                        uniformly random 32-byte arrays, or
                                        equal to zero. 1 otherwise,
                                        pointer to a public key object)
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate public key
    utils.validate_public_key(pubkey)

    # Validate tweak
    utils.validate_tweak_ser(tweak)

    return (lib.secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak), pubkey)


def context_randomize(ctx, seed32):
    '''Updates the context randomization to protect against side-channel leakage.

    While secp256k1 code is written to be constant-time no matter what secret
    values are, it's possible that a future compiler may output code which
    isn't, and also that the CPU may not emit the same radio frequencies or
    draw the same amount power for all values.

    This function provides a seed which is combined into the blinding value:
    that blinding value is added before each multiplication (and removed
    afterwards) so that it does not affect function results, but shields
    against attacks which rely on any input-dependent behaviour.

    You should call this after secp256k1_context_create or
    secp256k1_context_clone, and may call this repeatedly afterwards.

    Args:
        ctx     (secp256k1_context*):   pointer to a context object (cannot be
                                        NULL)
        seed32  (bytes):                pointer to a 32-byte random seed (NULL
                                        resets to initial state)
    Returns:
        (int):                          1 if randomization successfully updated
                                        0 if error
    '''
    # Validate context
    utils.validate_context(ctx)

    # Validate seed32
    utils.validate_bytes_type(
        seed32, [32], 'Invalid seed32. Must be 32-bytes.')

    return lib.secp256k1_context_randomize(ctx, seed32)


def ec_pubkey_combine(ctx, pubkeys):
    '''Add a number of public keys together.
    Args:
        ctx	(secp256k1_context*):   pointer to a context object
        pubkeys	(list):			list of pubkeys to add together
    Returns:
        (int, secp256k1_pubkey*):   	(1: the sum of the public keys is valid
                                        0: the sum of the public keys is not
                                        valid,
                                        pointer to a public key object for
                                        placing the resulting public key
                                        (cannot be NULL))
    '''
    # Validate context
    utils.validate_context(ctx)

    # Number of public keys to add together
    n = len(pubkeys)

    # Pointer to array of pointers to public keys (cannot be null)
    ins = ffi.new('secp256k1_pubkey[]', n)
    ins = ffi.new(
        'secp256k1_pubkey*[]',
        [pk.as_cffi_pointer() for pk in pubkeys])

    # Pointer to a public key object for placing the resulting public key
    out = ffi.new('secp256k1_pubkey *')

    return (lib.secp256k1_ec_pubkey_combine(ctx, out, ins, n), out)


# def ecdh(ctx, pubkey, privkey):
#     '''Compute an EC Diffie-Hellman secret in constant time
#     Args:
#         ctx     (secp256k1_context*):   pointer to a context object (cannot
#                                         be NULL)
#         pubkey  (secp256k1_pubkey):     a pointer to a secp256k1_pubkey
#                                         containing an initialized public key
#         privkey (bytes):                a 32-byte scalar with which to
#                                         multiply the point
#     Returns:
#         (int, bytes):                  (1: exponentiation was successful
#                                         0: scalar was invalid (zero or
#                                         overflow),
#                                         a 32-byte array which will be filled
#                                         by an ECDH secret computed from the
#                                         point and scalar
#     '''
#     # Validate context
#     utils.validate_context(ctx)
#
#     # Validate public key
#     utils.validate_public_key(pubkey)
#
#     # Validate serialized private key
#     utils.validate_secret_key_ser(privkey)
#
#     # A 32-byte array which will be populated by an ECDH secret computed from
#     # the point and scalar
#     result = ffi.new('char[]', 32)
#
#     return (lib.secp256k1_ecdh(ctx, result, pubkey, privkey), result)
