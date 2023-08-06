import codecs
import hashlib


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


def decode_hex(s: str) -> bytes:
    """
    Decode hex string to bytes. `0x` prefix is optional.

    Parameters
    ----------
    s: str
        hex string

    Returns
    -------
    bytes
        decoded bytes

    >>> decode_hex('0x7468697320697320612074657374') == b'this is a test'
    True
    """
    return codecs.decode(remove_0x(s), "hex")


# private below
def remove_0x(s: str) -> str:
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s
