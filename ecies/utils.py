import hashlib
import codecs

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from coincurve import PrivateKey, PublicKey
from coincurve.utils import get_valid_secret
from eth_keys import keys

AES_CIPHER_MODE = AES.MODE_GCM
AES_KEY_BYTES_LEN = 32

__all__ = [
    "sha256",
    "generate_key",
    "generate_eth_key",
    "hex2prv",
    "hex2pub",
    "aes_encrypt",
    "aes_decrypt",
]


def remove_0x(s: str) -> str:
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s


def decode_hex(s: str) -> bytes:
    return codecs.decode(remove_0x(s), "hex")  # type: ignore


def sha256(msg: bytes) -> bytes:
    """
    Calculate sha256 hash.

    Parameters
    ----------
    msg: bytes
        message to hash

    Returns
    -------
    bytes
        sha256 hash in bytes

    >>> sha256(b'0'*16).hex()[:8] == 'fcdb4b42'
    True
    """
    return hashlib.sha256(msg).digest()


def generate_key() -> PrivateKey:
    """
    Generate random (or disposable) EC private key

    Returns
    -------
    coincurve.PrivateKey
        A secp256k1 key

    >>> k = generate_key()
    """
    return PrivateKey(get_valid_secret())


def generate_eth_key() -> keys.PrivateKey:
    """
    Generate random eth private key

    Returns
    -------
    eth_keys.keys.PrivateKey
        An ethereum key

    >>> k = generate_eth_key()
    """
    return keys.PrivateKey(get_valid_secret())


def hex2pub(pub_hex: str) -> PublicKey:
    """
    Convert ethereum hex to EllipticCurvePublicKey
    The hex should be 65 bytes, but ethereum public key only has 64 bytes
    So have to add \x04

    Parameters
    ----------
    pub_hex: str
        Public key hex string

    Returns
    -------
    coincurve.PublicKey
        A secp256k1 public key

    >>> data = b'0'*32
    >>> data_hash = sha256(data)
    >>> eth_prv = generate_eth_key()
    >>> cc_prv = hex2prv(eth_prv.to_hex())
    >>> eth_prv.sign_msg_hash(data_hash).to_bytes() == cc_prv.sign_recoverable(data)
    True
    >>> pk_hex = eth_prv.public_key.to_hex()
    >>> computed_pub = hex2pub(pk_hex)
    >>> computed_pub == cc_prv.public_key
    True
    """
    uncompressed = decode_hex(pub_hex)
    if len(uncompressed) == 64:  # eth public key format
        uncompressed = b"\x04" + uncompressed

    return PublicKey(uncompressed)


def hex2prv(prv_hex: str) -> PrivateKey:
    """
    Convert ethereum hex to EllipticCurvePrivateKey

    Parameters
    ----------
    prv_hex: str
        Private key hex string

    Returns
    -------
    coincurve.PrivateKey
        A secp256k1 private key

    >>> k = generate_eth_key()
    >>> sk_hex = k.to_hex()
    >>> pk_hex = k.public_key.to_hex()
    >>> computed_prv = hex2prv(sk_hex)
    >>> computed_prv.to_int() == int(k.to_hex(), 16)
    True
    """
    return PrivateKey(decode_hex(prv_hex))


def encapsulate(private_key: PrivateKey, peer_public_key: PublicKey) -> bytes:
    shared_point = peer_public_key.multiply(private_key.secret)
    master = private_key.public_key.format(compressed=False) + shared_point.format(
        compressed=False
    )
    derived = HKDF(master, AES_KEY_BYTES_LEN, b"", SHA256)
    return derived  # type: ignore


def decapsulate(public_key: PublicKey, peer_private_key: PrivateKey) -> bytes:
    shared_point = public_key.multiply(peer_private_key.secret)
    master = public_key.format(compressed=False) + shared_point.format(compressed=False)
    derived = HKDF(master, AES_KEY_BYTES_LEN, b"", SHA256)
    return derived  # type: ignore


def aes_encrypt(key: bytes, plain_text: bytes) -> bytes:
    """
    AES-GCM encryption

    Parameters
    ----------
    key: bytes
        AES session key, which derived from two secp256k1 keys
    plain_text: bytes
        Plain text to encrypt

    Returns
    -------
    bytes
        nonce(16 bytes) + tag(16 bytes) + encrypted data
    """
    aes_cipher = AES.new(key, AES_CIPHER_MODE)

    encrypted, tag = aes_cipher.encrypt_and_digest(plain_text)  # type: ignore
    cipher_text = bytearray()
    cipher_text.extend(aes_cipher.nonce)  # type: ignore
    cipher_text.extend(tag)
    cipher_text.extend(encrypted)
    return bytes(cipher_text)


def aes_decrypt(key: bytes, cipher_text: bytes) -> bytes:
    """
    AES-GCM decryption

    Parameters
    ----------
    key: bytes
        AES session key, which derived from two secp256k1 keys
    cipher_text: bytes
        Encrypted text:
            iv(16 bytes) + tag(16 bytes) + encrypted data

    Returns
    -------
    bytes
        Plain text

    >>> data = b'this is test data'
    >>> key = get_valid_secret()
    >>> aes_decrypt(key, aes_encrypt(key, data)) == data
    True
    >>> import os
    >>> key = os.urandom(32)
    >>> aes_decrypt(key, aes_encrypt(key, data)) == data
    True
    """
    iv = cipher_text[:16]
    tag = cipher_text[16:32]
    ciphered_data = cipher_text[32:]

    # NOTE
    # pycryptodome's aes gcm takes nonce as iv
    # but actually nonce (12 bytes) should be used to generate iv (16 bytes) and iv should be sequential
    # See https://crypto.stackexchange.com/a/71219
    aes_cipher = AES.new(key, AES_CIPHER_MODE, nonce=iv)
    return aes_cipher.decrypt_and_verify(ciphered_data, tag)  # type: ignore
