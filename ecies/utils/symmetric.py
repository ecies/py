import os

from Crypto.Cipher import AES, ChaCha20_Poly1305

from ..config import NonceLength, SymmetricAlgorithm
from ..consts import AEAD_TAG_LENGTH, XCHACHA20_NONCE_LENGTH


def sym_encrypt(
    key: bytes,
    plain_text: bytes,
    algorithm: SymmetricAlgorithm = "aes-256-gcm",
    nonce_length: NonceLength = 16,
) -> bytes:
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
    if algorithm == "aes-256-gcm":
        nonce = os.urandom(nonce_length)
        aes_cipher = AES.new(key, AES.MODE_GCM, nonce)
        encrypted, tag = aes_cipher.encrypt_and_digest(plain_text)
    elif algorithm == "xchacha20":
        nonce = os.urandom(XCHACHA20_NONCE_LENGTH)
        chacha_cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        encrypted, tag = chacha_cipher.encrypt_and_digest(plain_text)
    else:
        raise NotImplementedError

    cipher_text = bytearray()
    cipher_text.extend(nonce)
    cipher_text.extend(tag)
    cipher_text.extend(encrypted)
    return bytes(cipher_text)


def sym_decrypt(
    key: bytes,
    cipher_text: bytes,
    algorithm: SymmetricAlgorithm = "aes-256-gcm",
    nonce_length: NonceLength = 16,
) -> bytes:
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

    if algorithm == "aes-256-gcm":
        nonce, tag, ciphered_data = __split_cipher_text(cipher_text, nonce_length)
        aes_cipher = AES.new(key, AES.MODE_GCM, nonce)
        return aes_cipher.decrypt_and_verify(ciphered_data, tag)
    elif algorithm == "xchacha20":
        nonce, tag, ciphered_data = __split_cipher_text(
            cipher_text, XCHACHA20_NONCE_LENGTH
        )
        xchacha_cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        return xchacha_cipher.decrypt_and_verify(ciphered_data, tag)
    else:
        raise NotImplementedError


def __split_cipher_text(cipher_text: bytes, nonce_length: int):
    nonce_tag_length = nonce_length + AEAD_TAG_LENGTH
    nonce = cipher_text[:nonce_length]
    tag = cipher_text[nonce_length:nonce_tag_length]
    ciphered_data = cipher_text[nonce_tag_length:]
    return nonce, tag, ciphered_data
