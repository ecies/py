from typing import Union

from coincurve import PrivateKey, PublicKey

from .config import ECIES_CONFIG, Config
from .utils import (
    bytes2pk,
    decapsulate,
    encapsulate,
    generate_key,
    hex2pk,
    hex2sk,
    sym_decrypt,
    sym_encrypt,
)

__all__ = ["encrypt", "decrypt", "ECIES_CONFIG"]


def encrypt(
    receiver_pk: Union[str, bytes], data: bytes, config: Config = ECIES_CONFIG
) -> bytes:
    """
    Encrypt with receiver's secp256k1 public key

    Parameters
    ----------
    receiver_pk: Union[str, bytes]
        Receiver's public key (hex `str` or `bytes`)
    data: bytes
        Data to encrypt
    config: Config
        Optional configuration object

    Returns
    -------
    bytes
        Encrypted data
    """
    if isinstance(receiver_pk, str):
        pk = hex2pk(receiver_pk)
    elif isinstance(receiver_pk, bytes):
        pk = bytes2pk(receiver_pk)
    else:
        raise TypeError("Invalid public key type")

    ephemeral_sk = generate_key()
    ephemeral_pk = ephemeral_sk.public_key.format(config.is_ephemeral_key_compressed)

    sym_key = encapsulate(ephemeral_sk, pk, config.is_hkdf_key_compressed)
    encrypted = sym_encrypt(
        sym_key, data, config.symmetric_algorithm, config.symmetric_nonce_length
    )
    return ephemeral_pk + encrypted


def decrypt(
    receiver_sk: Union[str, bytes], data: bytes, config: Config = ECIES_CONFIG
) -> bytes:
    """
    Decrypt with receiver's secp256k1 private key

    Parameters
    ----------
    receiver_sk: Union[str, bytes]
        Receiver's private key (hex `str` or `bytes`)
    data: bytes
        Data to decrypt
    config: Config
        Optional configuration object

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
    ephemeral_pk, encrypted = PublicKey(data[0:key_size]), data[key_size:]

    sym_key = decapsulate(ephemeral_pk, sk, config.is_hkdf_key_compressed)
    return sym_decrypt(
        sym_key, encrypted, config.symmetric_algorithm, config.symmetric_nonce_length
    )
