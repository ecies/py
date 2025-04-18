from coincurve.utils import get_valid_secret
from Crypto.Hash import keccak
from typing_extensions import deprecated


@deprecated(
    "Use `eth_keys.keys.PrivateKey(coincurve.utils.get_valid_secret())` instead"
)
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


# for cli only
def to_eth_address(pk_bytes: bytes) -> str:
    if len(pk_bytes) != 64:
        raise NotImplementedError
    return encode_checksum(keccak256(pk_bytes)[-20:].hex())


# private below
def encode_checksum(raw_address: str) -> str:
    # https://github.com/ethereum/ercs/blob/master/ERCS/erc-55.md
    address = raw_address.lower().replace("0x", "")
    address_hash = keccak256(address.encode()).hex()

    res = []
    for a, h in zip(address, address_hash):
        if int(h, 16) >= 8:
            res.append(a.upper())
        else:
            res.append(a)

    return "0x" + "".join(res)


def keccak256(data: bytes) -> bytes:
    h = keccak.new(data=data, digest_bits=256)
    return h.digest()
