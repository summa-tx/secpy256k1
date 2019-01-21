import secpy256k1
from secpy256k1 import utils

from typing import Callable


def get_sign_context():
    '''
    Convenience function to create a libsecp256k1 signing context
    '''
    return secpy256k1.context_create(secpy256k1.lib.SECP256K1_CONTEXT_SIGN)


def get_verify_context():
    '''
    Convenience function to create a libsecp256k1 verification context
    '''
    return secpy256k1.context_create(secpy256k1.lib.SECP256K1_CONTEXT_VERIFY)


def sign_hash(privkey: bytes, digest: bytes) -> bytes:
    '''
    Signs the digest of a message with the private key
    Args:
        privkey (bytes): 32 byte private key
        digest  (bytes): 32 byte hash
    Returns:
        (bytes): der encoded signature
    '''
    if len(digest) != 32:
        raise ValueError('Digest must be 32 bytes')

    ctx = get_sign_context()

    if secpy256k1.ec_seckey_verify(privkey) != 1:
        raise Exception('unknown exception -- seckey verify failed')

    sig_tuple = secpy256k1.ecdsa_sign(ctx, digest, privkey)

    if sig_tuple[0] != 1:
        raise Exception('unknown exception -- sign failed')

    der_sig_tuple = secpy256k1.ecdsa_signature_serialize_der(
        ctx,
        sig_tuple[1])

    if der_sig_tuple[0] != 1:
        raise Exception('unknown exception -- der ser failed')

    return bytes(secpy256k1.ffi.buffer(der_sig_tuple[1]))


def sign(
        privkey: bytes,
        msg: bytes,
        hash_func: Callable[[bytes], bytes] = utils.sha256) -> bytes:
    '''
    Signs the digest of a message with the private key
    Args:
        privkey      (bytes): 32 byte private key
        msg          (bytes): msg to sign
        hash_func (callable): a hash function that produces 32 byte output
    Returns:
        (bytes): der encoded signature
    '''
    msg_hash = hash_func(msg)

    return sign_hash(privkey, msg_hash)


def verify_hash(
        pubkey: bytes,
        sig: bytes,
        digest: bytes) -> bool:
    '''
    Verifies a signature on a specific hash

    NB: ECDSA is NOT SECURE unless the verifier calculates the hash

    Args:
        pubkey (bytes): the public key in compressed or uncompressed form
        sig    (bytes): the der encoded signature
        digest (bytes): the 32 byte message digest
    Returns:
        (bool): True if valid signature, false otherwise
    '''
    if len(digest) != 32:
        raise ValueError('Digest must be 32 bytes')

    ctx = get_verify_context()

    pubkey_tuple = secpy256k1.ec_pubkey_parse(ctx, pubkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey parse failed')

    sig_tuple = secpy256k1.ecdsa_signature_parse_der(ctx, sig)

    if sig_tuple[0] != 1:
        raise Exception('unknown exception -- sig parse failed')

    res = secpy256k1.ecdsa_verify(ctx, sig_tuple[1], digest, pubkey_tuple[1])

    return True if res == 1 else False


def verify(
        pubkey: bytes,
        sig: bytes,
        msg: bytes,
        hash_func: Callable[[bytes], bytes] = utils.sha256) -> bool:
    '''
    Verifies a signature on a message
    Args:
        pubkey (bytes): the public key in compressed or uncompressed form
        sig    (bytes): the der encoded signature
        msg    (bytes): the message to sign
        hash_func (callable): a hash function that produces a 32 byte digest
    Returns:
        (bool): True if valid signature, false otherwise
    '''
    msg_hash = hash_func(msg)
    return verify_hash(pubkey, sig, msg_hash)


def priv_to_pub(privkey: bytes, compressed: bool = True) -> bytes:
    '''
    Returns the pubkey for a given privkey
    Args:
        privkey   (bytes): the 32 byte secret key
        compressed (bool): True for compressed (33 byte),
                           False for uncompressed (65 byte)
    Returns:
        (bytes): 33 (compressed) or 65 (uncompressed) byte pubkey
    '''
    ctx = get_sign_context()

    pubkey_tuple = secpy256k1.ec_pubkey_create(ctx, privkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey create failed')

    flags = (secpy256k1.lib.SECP256K1_EC_COMPRESSED if compressed
             else secpy256k1.lib.SECP256K1_EC_UNCOMPRESSED)

    pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
        ctx,
        pubkey_tuple[1],
        flags)

    if pubkey_ser_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey serialize failed')

    return bytes(secpy256k1.ffi.buffer(pubkey_ser_tuple[1]))


def uncompress_pubkey(pubkey: bytes) -> bytes:
    '''
    Converts a compressed pubkey to an uncompressed pubkey
    Args:
        pubkey (bytes): the 33 byte compressed key
    Returns:
        (bytes): the uncompressed (65 byte) pubkey
    '''
    ctx = get_verify_context()

    pubkey_tuple = secpy256k1.ec_pubkey_parse(ctx, pubkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey parse failed')

    pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
        ctx,
        pubkey_tuple[1],
        secpy256k1.lib.SECP256K1_EC_UNCOMPRESSED)

    if pubkey_ser_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey ser failed')

    return bytes(secpy256k1.ffi.buffer(pubkey_ser_tuple[1]))


def compress_pubkey(pubkey: bytes) -> bytes:
    '''
    Converts an uncompressed pubkey to a compressed pubkey
    Args:
        pubkey (bytes): the 65 byte uncompressed key
    Returns:
        (bytes): the compressed (33 byte) pubkey
    '''
    ctx = get_verify_context()

    pubkey_tuple = secpy256k1.ec_pubkey_parse(ctx, pubkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey parse failed')

    pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
        ctx,
        pubkey_tuple[1],
        secpy256k1.lib.SECP256K1_EC_COMPRESSED)

    if pubkey_ser_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey ser failed')

    return bytes(secpy256k1.ffi.buffer(pubkey_ser_tuple[1]))


def tweak_pubkey_add(
        pubkey: bytes,
        tweak: bytes,
        compressed: bool = True) -> bytes:
    '''
    Tweaks a pubkey by adding a 32 byte tweak times the generator to it
    Args:
        pubkey (bytes): 32 byte pubkey
        tweak   (bytes): 32 byte tweak
    Returns:
        (bytes): 32 byte tweaked pubkey
    '''
    ctx = get_verify_context()

    if len(tweak) != 32:
        raise ValueError('tweak must be 32 bytes')

    pubkey_tuple = secpy256k1.ec_pubkey_parse(ctx, pubkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey parse failed')

    tweaked_tuple = secpy256k1.ec_pubkey_tweak_add(ctx, pubkey_tuple[1], tweak)

    if tweaked_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey tweak add failed')

    flag = (secpy256k1.lib.SECP256K1_EC_COMPRESSED
            if compressed else
            secpy256k1.lib.SECP256K1_EC_UNCOMPRESSED)
    pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
        ctx,
        tweaked_tuple[1],
        flag)

    if pubkey_ser_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey ser failed')

    return bytes(secpy256k1.ffi.buffer(pubkey_ser_tuple[1]))


def tweak_pubkey_mul(
        pubkey: bytes,
        tweak: bytes,
        compressed: bool = True) -> bytes:
    '''
    Tweaks a pubkey by multiplying by a 32 byte tweak
    Args:
        pubkey (bytes): 32 byte pubkey
        tweak   (bytes): 32 byte tweak
    Returns:
        (bytes): 32 byte tweaked pubkey
    '''
    ctx = get_verify_context()

    if len(tweak) != 32:
        raise ValueError('tweak must be 32 bytes')

    pubkey_tuple = secpy256k1.ec_pubkey_parse(ctx, pubkey)

    if pubkey_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey parse failed')

    tweaked_tuple = secpy256k1.ec_pubkey_tweak_mul(ctx, pubkey_tuple[1], tweak)

    if tweaked_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey tweak mul failed')

    flag = (secpy256k1.lib.SECP256K1_EC_COMPRESSED
            if compressed else
            secpy256k1.lib.SECP256K1_EC_UNCOMPRESSED)
    pubkey_ser_tuple = secpy256k1.ec_pubkey_serialize(
        ctx,
        tweaked_tuple[1],
        flag)

    if pubkey_ser_tuple[0] != 1:
        raise Exception('unknown exception -- pubkey ser failed')

    return bytes(secpy256k1.ffi.buffer(pubkey_ser_tuple[1]))


def tweak_privkey_add(privkey: bytes, tweak: bytes) -> bytes:
    '''
    Tweaks a privkey by adding a 32-byte tweak to it
    Args:
        privkey (bytes): 32 byte privkey
        tweak   (bytes): 32 byte tweak
    Returns:
        (bytes): 32 byte tweaked privkey
    '''

    ctx = get_sign_context()

    if len(tweak) != 32:
        raise ValueError('tweak must be 32 bytes')

    if len(privkey) != 32:
        raise ValueError('privkey must be 32 bytes')

    tweak_tuple = secpy256k1.ec_privkey_tweak_add(ctx, privkey, tweak)

    if tweak_tuple[0] != 1:
        raise Exception('unknown exception -- privkey tweak failed')

    return tweak_tuple[1]


def tweak_privkey_mul(privkey: bytes, tweak: bytes) -> bytes:
    '''
    Tweaks a privkey by multiplying it by a 32-byte tweak
    Args:
        privkey (bytes): 32 byte privkey
        tweak   (bytes): 32 byte tweak
    Returns:
        (bytes): 32 byte tweaked privkey
    '''
    ctx = get_sign_context()

    if len(tweak) != 32:
        raise ValueError('tweak must be 32 bytes')

    if len(privkey) != 32:
        raise ValueError('privkey must be 32 bytes')

    tweak_tuple = secpy256k1.ec_privkey_tweak_mul(ctx, privkey, tweak)

    if tweak_tuple[0] != 1:
        raise Exception('unknown exception -- privkey tweak failed')

    return tweak_tuple[1]
