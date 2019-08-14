from typing import Union

from coincurve import PrivateKey, PublicKey
from ecies.utils import generate_key, hex2prv, hex2pub, encapsulate, decapsulate, aes_encrypt, aes_decrypt

__all__ = ["encrypt", "decrypt"]


def encrypt(receiver_pk: Union[str, bytes], msg: bytes) -> bytes:
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
    ephemeral_key = generate_key()
    if isinstance(receiver_pk, str):
        receiver_pubkey = hex2pub(receiver_pk)
    elif isinstance(receiver_pk, bytes):
        receiver_pubkey = PublicKey(receiver_pk)
    else:
        raise TypeError("Invalid public key type")

    aes_key = encapsulate(ephemeral_key, receiver_pubkey)
    cipher_text = aes_encrypt(aes_key, msg)
    return ephemeral_key.public_key.format(False) + cipher_text


def decrypt(receiver_sk: Union[str, bytes], msg: bytes) -> bytes:
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
        private_key = hex2prv(receiver_sk)
    elif isinstance(receiver_sk, bytes):
        private_key = PrivateKey(receiver_sk)
    else:
        raise TypeError("Invalid secret key type")

    pubkey = msg[0:65]  # uncompressed pubkey's length is 65 bytes
    encrypted = msg[65:]
    ephemeral_public_key = PublicKey(pubkey)

    aes_key = decapsulate(ephemeral_public_key, private_key)
    return aes_decrypt(aes_key, encrypted)
