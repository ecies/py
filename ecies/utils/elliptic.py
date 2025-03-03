from coincurve import PrivateKey, PublicKey
from coincurve.utils import get_valid_secret

from .hash import derive_key
from .hex import decode_hex


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


def generate_eth_key():
    """
    Note: `eth-keys` needs to be installed in advance.

    Generate a random `eth_keys.keys.PrivateKey`

    Returns
    -------
    eth_keys.keys.PrivateKey
        An ethereum flavored secp256k1 key

    """
    from eth_keys import keys

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

    """
    return PublicKey(compat_eth_public_key(decode_hex(pk_hex)))


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

    """
    return PrivateKey(decode_hex(sk_hex))


def compat_eth_public_key(data: bytes):
    """
    Convert ethereum public key to uncompressed public key

    Parameters
    ----------
    data: bytes
        Ethereum public key (64 bytes)

    Returns
    -------
    bytes
        Uncompressed public key (65 bytes)

    """
    if len(data) == 64:
        data = b"\x04" + data
    return data


# private below
def encapsulate(
    private_key: PrivateKey, peer_public_key: PublicKey, is_compressed: bool = False
) -> bytes:
    shared_point = peer_public_key.multiply(private_key.secret)
    master = private_key.public_key.format(is_compressed) + shared_point.format(
        is_compressed
    )
    return derive_key(master)


def decapsulate(
    public_key: PublicKey, peer_private_key: PrivateKey, is_compressed: bool = False
) -> bytes:
    shared_point = public_key.multiply(peer_private_key.secret)
    master = public_key.format(is_compressed) + shared_point.format(is_compressed)
    return derive_key(master)
