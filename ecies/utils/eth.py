from coincurve import PublicKey
from coincurve.utils import get_valid_secret

from ..consts import ETH_PUBLIC_KEY_LENGTH
from .hash import keccak256


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
def to_eth_public_key(pk: PublicKey) -> bytes:
    return pk.format(False)[1:]


def to_eth_address(pk: PublicKey) -> str:
    pk_bytes = to_eth_public_key(pk)
    return encode_checksum(keccak256(pk_bytes)[-20:].hex())


# private below
def convert_eth_public_key(data: bytes):
    if len(data) == ETH_PUBLIC_KEY_LENGTH:
        data = b"\x04" + data
    return data


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
