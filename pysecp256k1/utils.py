from _secp256k1 import ffi


def _validate_cdata_type(value, type_str, err_msg, null_flag=False):
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

    elif null_flag and value is not ffi.NULL:
        raise TypeError(err_msg)

    return True


def validate_context(ctx):
    '''Checks that context is a valid secp256k1_context struct pointer.
    Args:
        ctx (secp256k1_context):    a secp256k1 context object
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
            (True):                         if sig is valid, otherwise error
    '''
    return _validate_cdata_type(
            sig,
            'secp256k1_ecdsa_signature *',
            'Invalid sig. Must be secp256k1_ecdsa_signature pointer.')


def validate_noncefp(noncefp):
    '''Checks that noncefp is a valid secp256k1_nonce_function pointer or NULL.
    Args:
        noncefp (secp256k1_nonce_function*):    pointer to secp256k1 nonce
                                                generation function or NULL
    Returns:
                (True):                         if noncefp is valid, otherwise
                                                error
    '''
    if noncefp is ffi.NULL:
        return True

    return _validate_cdata_type(
            noncefp,
            'secp256k1_nonce_function *',
            'Invalid noncefp. Must be secp256k1_nonce_function pointer.')


def validate_secret_key_ser(seckey):
    '''Checks that the serialized secret key is a valid byte string.
    Args:
        seckey  (bytes):                pointer to a 32-byte secret key (cannot
                                        be NULL)
    Returns:
                (True):                 if seckey is valid, otherwise error
    '''
    if not isinstance(seckey, bytes) or len(seckey) != 32:
        raise ValueError('Invalid msg. Must be 32-bytes.')

    return True


def validate_public_key_ser(pubkey):
    '''Checks that the serialized public key is a valid byte string.
    Args:
        pubkey  (bytes):                pointer to a serialized public key
    Returns:
                (True):                 if pubkey is valid, otherwise error
    '''
    if not isinstance(pubkey, bytes) or len(pubkey) not in [33, 65]:
        raise ValueError('Invalid pubkey. Must be 33- or 65-bytes.')

    return True


def validate_msg32_ser(msg32):
    '''Checks that the serialized message is a valid byte string.
    Args:
        msg32   (bytes):                the 32-byte message hash being verified
                                        (cannot be NULL)
    Returns:
                (True):                 if msg32 is valid, otherwise error
    '''
    if not isinstance(msg32, bytes) or len(msg32) != 32:
        raise ValueError('Invalid msg32. Must be 32-bytes.')

    return True


def validate_tweak_ser(tweak):
    '''Checks that the serialized tweak is a valid byte string.
    Args:
        tweak   (bytes):                a 32-byte tweak (cannot be NULL)
    Returns:
                (True):                 if tweak is valid, otherwise error
    '''
    if not isinstance(tweak, bytes) or len(tweak) != 32:
                raise ValueError('Invalid tweak. Must be 32-bytes.')

    return True


def validate_ndata(ndata):
    '''Checks that ndata is a valid ctype or NULL.
    Args:
        ndata   (void*):                pointer to arbitrary data used by the
                                        nonce generation function (can be NULL)
    Returns:
                (True):                 if ndata is valid, otherwise error
    '''
    return _validate_cdata_type(
            value=ndata,
            type_str=ffi.NULL,
            err_msg='Invalid ndata. Must be valid cdata type or NULL.',
            null_flag=True)
