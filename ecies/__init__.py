from typing import Union

from coincurve import PrivateKey, PublicKey

from .config import ECIES_CONFIG, Config
from .utils import (
    decapsulate,
    encapsulate,
    generate_key,
    hex2pk,
    hex2sk,
    sym_decrypt,
    sym_encrypt,
)

__all__ = ["encrypt", "decrypt", "ECIES_CONFIG"]


def encrypt(receiver_pk: Union[str, bytes], msg: bytes, config: Config = ECIES_CONFIG) -> bytes:
    """
    Encrypt with receiver's secp256k1 public key

    Parameters
    ----------
    receiver_pk: Union[str, bytes]
        Receiver's public key (hex str or bytes)
    msg: bytes
        Data to encrypt

    Returns
    -------
    bytes
        Encrypted data
    """
    if isinstance(receiver_pk, str):
        pk = hex2pk(receiver_pk)
    elif isinstance(receiver_pk, bytes):
        pk = PublicKey(receiver_pk)
    else:
        raise TypeError("Invalid public key type")

    ephemeral_sk = generate_key()
    ephemeral_pk = ephemeral_sk.public_key.format(
        config.is_ephemeral_key_compressed
    )

    sym_key = encapsulate(ephemeral_sk, pk, config)
    encrypted = sym_encrypt(sym_key, msg, config)
    return ephemeral_pk + encrypted


def decrypt(receiver_sk: Union[str, bytes], msg: bytes, config: Config = ECIES_CONFIG) -> bytes:
    """
    Decrypt with receiver's secp256k1 private key

    Parameters
    ----------
    receiver_sk: Union[str, bytes]
        Receiver's private key (hex str or bytes)
    msg: bytes
        Data to decrypt

    Returns
    -------
    bytes
        Plain text
    """
    if isinstance(receiver_sk, str):
        sk = hex2sk(receiver_sk)
    elif isinstance(receiver_sk, bytes):
        sk = PrivateKey(receiver_sk)
    else:
        raise TypeError("Invalid secret key type")

    key_size = config.ephemeral_key_size
    ephemeral_pk, encrypted = PublicKey(msg[0:key_size]), msg[key_size:]

    sym_key = decapsulate(ephemeral_pk, sk, config)
    return sym_decrypt(sym_key, encrypted, config)
