import os

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from ..config import ECIES_CONFIG

AES_CIPHER_MODE = AES.MODE_GCM
AEAD_TAG_LENGTH = 16
XCHACHA20_NONCE_LENGTH = 24


def sym_encrypt(key: bytes, plain_text: bytes) -> bytes:
    """
    Symmetric encryption. AES-256-GCM or XChaCha20-Poly1305.

    Nonce may be 12/16 bytes on AES, 24 bytes on XChaCha. Default is AES-256-GCM with 16 bytes nonce.

    Parameters
    ----------
    key: bytes
        Symmetric encryption session key, which derived from two secp256k1 keys
    plain_text: bytes
        Plain text to encrypt

    Returns
    -------
    bytes
        nonce + tag(16 bytes) + encrypted data
    """
    algorithm = ECIES_CONFIG.symmetric_algorithm
    if algorithm == "aes-256-gcm":
        nonce_length = ECIES_CONFIG.symmetric_nonce_length
        nonce = os.urandom(nonce_length)
        cipher = AES.new(key, AES_CIPHER_MODE, nonce)
    elif algorithm == "xchacha20":
        nonce = os.urandom(XCHACHA20_NONCE_LENGTH)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)  # type:ignore
    else:
        raise NotImplementedError

    encrypted, tag = cipher.encrypt_and_digest(plain_text)
    cipher_text = bytearray()
    cipher_text.extend(nonce)
    cipher_text.extend(tag)
    cipher_text.extend(encrypted)
    return bytes(cipher_text)


def sym_decrypt(key: bytes, cipher_text: bytes) -> bytes:
    """
    AES-GCM decryption. AES-256-GCM or XChaCha20-Poly1305.

    Parameters
    ----------
    key: bytes
        Symmetric encryption session key, which derived from two secp256k1 keys
    cipher_text: bytes
        Encrypted text:
            nonce + tag(16 bytes) + encrypted data

    Returns
    -------
    bytes
        Plain text

    >>> from coincurve.utils import get_valid_secret
    >>> data = b'this is test data'
    >>> key = get_valid_secret()
    >>> sym_decrypt(key, sym_encrypt(key, data)) == data
    True
    >>> import os
    >>> key = os.urandom(32)
    >>> sym_decrypt(key, sym_encrypt(key, data)) == data
    True
    """

    # NOTE
    # pycryptodome's aes gcm takes nonce as iv
    # but actually nonce (12 bytes) should be used to generate iv (16 bytes) and iv should be sequential
    # See https://crypto.stackexchange.com/a/71219
    # You can configure to use 12 bytes nonce by setting `ECIES_CONFIG.symmetric_nonce_length = 12`
    # If it's 12 bytes, the nonce can be incremented by 1 for each encryption
    # If it's 16 bytes, the nonce will be used to hash, so it's meaningless to increment

    algorithm = ECIES_CONFIG.symmetric_algorithm
    if algorithm == "aes-256-gcm":
        nonce_length = ECIES_CONFIG.symmetric_nonce_length
        nonce_tag_length = nonce_length + AEAD_TAG_LENGTH
        nonce = cipher_text[:nonce_length]
        tag = cipher_text[nonce_length:nonce_tag_length]
        ciphered_data = cipher_text[nonce_tag_length:]
        cipher = AES.new(key, AES_CIPHER_MODE, nonce)
    elif algorithm == "xchacha20":
        nonce_tag_length = XCHACHA20_NONCE_LENGTH + AEAD_TAG_LENGTH
        nonce = cipher_text[:XCHACHA20_NONCE_LENGTH]
        tag = cipher_text[XCHACHA20_NONCE_LENGTH:nonce_tag_length]
        ciphered_data = cipher_text[nonce_tag_length:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)  # type:ignore
    else:
        raise NotImplementedError
    return cipher.decrypt_and_verify(ciphered_data, tag)


def derive_key(master: bytes) -> bytes:
    derived = HKDF(master, 32, b"", SHA256)
    return derived  # type: ignore
