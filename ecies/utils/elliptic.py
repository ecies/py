from coincurve import PrivateKey, PublicKey
from coincurve.utils import get_valid_secret
from eth_keys import keys

from ..config import ECIES_CONFIG
from .hex import decode_hex
from .symmetric import derive_key


def generate_key() -> PrivateKey:
    """
    Generate a random coincurve.PrivateKey`

    Returns
    -------
    coincurve.PrivateKey
        A secp256k1 key

    >>> k = generate_key()
    """
    return PrivateKey(get_valid_secret())


def generate_eth_key() -> keys.PrivateKey:
    """
    Generate a random `eth_keys.keys.PrivateKey`

    Returns
    -------
    eth_keys.keys.PrivateKey
        An ethereum key

    >>> k = generate_eth_key()
    """
    return keys.PrivateKey(get_valid_secret())


def hex2pk(pk_hex: str) -> PublicKey:
    """
    Convert ethereum hex to `coincurve.PublicKey`
    The hex should be 65 bytes (uncompressed) or 33 bytes (compressed), but ethereum public key has 64 bytes.
    `0x04` will be appended if it's an ethereum public key.

    Parameters
    ----------
    pk_hex: str
        Public key hex string

    Returns
    -------
    coincurve.PublicKey
        A secp256k1 public key

    >>> from ecies.utils import sha256
    >>> data = b'0' * 32
    >>> data_hash = sha256(data)
    >>> eth_sk = generate_eth_key()
    >>> cc_sk = hex2sk(eth_sk.to_hex())
    >>> eth_sk.sign_msg_hash(data_hash).to_bytes() == cc_sk.sign_recoverable(data)
    True
    >>> pk_hex = eth_sk.public_key.to_hex()
    >>> computed_pk = hex2pk(pk_hex)
    >>> computed_pk == cc_sk.public_key
    True
    """
    uncompressed = decode_hex(pk_hex)
    if len(uncompressed) == 64:  # eth public key format
        uncompressed = b"\x04" + uncompressed

    return PublicKey(uncompressed)


def hex2sk(sk_hex: str) -> PrivateKey:
    """
    Convert ethereum hex to `coincurve.PrivateKey`

    Parameters
    ----------
    sk_hex: str
        Private key hex string

    Returns
    -------
    coincurve.PrivateKey
        A secp256k1 private key

    >>> k = generate_eth_key()
    >>> sk_hex = k.to_hex()
    >>> pk_hex = k.public_key.to_hex()
    >>> computed_sk = hex2sk(sk_hex)
    >>> computed_sk.to_int() == int(k.to_hex(), 16)
    True
    """
    return PrivateKey(decode_hex(sk_hex))


# private below
def encapsulate(private_key: PrivateKey, peer_public_key: PublicKey) -> bytes:
    is_compressed = ECIES_CONFIG.is_hkdf_key_compressed
    shared_point = peer_public_key.multiply(private_key.secret)
    master = private_key.public_key.format(is_compressed) + shared_point.format(
        is_compressed
    )
    return derive_key(master)


def decapsulate(public_key: PublicKey, peer_private_key: PrivateKey) -> bytes:
    is_compressed = ECIES_CONFIG.is_hkdf_key_compressed
    shared_point = public_key.multiply(peer_private_key.secret)
    master = public_key.format(is_compressed) + shared_point.format(is_compressed)
    return derive_key(master)
