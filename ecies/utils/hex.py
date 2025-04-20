import codecs


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
    """
    return codecs.decode(remove_0x(s), "hex")


# private below
def remove_0x(s: str) -> str:
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s
