r"""
 _______  _______ _________ _______  _______  _______
(  ____ \(  ____ \\__   __/(  ____ \(  ____ \(  ____ )|\     /|
| (    \/| (    \/   ) (   | (    \/| (    \/| (    )|( \   / )
| (__    | |         | |   | (__    | (_____ | (____)| \ (_) /
|  __)   | |         | |   |  __)   (_____  )|  _____)  \   /
| (      | |         | |   | (            ) || (         ) (
| (____/\| (____/\___) (___| (____/\/\____) || )         | |
(_______/(_______/\_______/(_______/\_______)|/          \_/

"""

import argparse
import sys

from ecies import decrypt, encrypt
from ecies.config import Config, EllipticCurve
from ecies.keys import PrivateKey
from ecies.utils import to_eth_address

__description__ = (
    "Elliptic Curve Integrated Encryption Scheme for secp256k1/curve25519 in Python"
)


def readablize(b: bytes) -> str:
    try:
        return b.decode()
    except ValueError:
        return b.hex()


def __generate(curve: EllipticCurve):
    k = PrivateKey(curve)
    pk_bytes = k.public_key.to_bytes()
    if curve == "secp256k1":
        eth_pk_bytes = pk_bytes[1:]
        sk, pk = f"0x{k.to_hex()}", f"0x{eth_pk_bytes.hex()}"
        address = to_eth_address(eth_pk_bytes)
        print("Private: {}\nPublic: {}\nAddress: {}".format(sk, pk, address))
    elif curve in ("x25519", "ed25519"):
        sk, pk = f"0x{k.to_hex()}", f"0x{pk_bytes.hex()}"
        print("Private: {}\nPublic: {}".format(sk, pk))
    else:
        raise NotImplementedError


def main():
    parser = argparse.ArgumentParser(description=__description__)

    parser.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="encrypt with public key, exclusive with -d",
    )
    parser.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="decrypt with private key, exclusive with -e",
    )
    parser.add_argument(
        "-g",
        "--generate",
        action="store_true",
        help="generate key pair, for secp256k1, ethereum public key and address will be printed",
    )
    parser.add_argument(
        "-k", "--key", type=argparse.FileType("r"), help="public or private key file"
    )
    parser.add_argument(
        "-c",
        "--curve",
        choices=["secp256k1", "x25519", "ed25519"],
        default="secp256k1",
        help="elliptic curve, default: secp256k1",
    )

    parser.add_argument(
        "-D",
        "--data",
        nargs="?",
        type=argparse.FileType("rb"),
        default=sys.stdin,
        help="file to encrypt or decrypt, if not specified, it will read from stdin",
    )

    parser.add_argument(
        "-O",
        "--out",
        nargs="?",
        type=argparse.FileType("wb"),
        default=sys.stdout,
        help="encrypted or decrypted file, if not specified, it will write to stdout",
    )

    args = parser.parse_args()
    if args.generate:
        __generate(args.curve)
        return

    if args.encrypt == args.decrypt:
        parser.print_help()
        return

    if not args.key:
        parser.print_help()
        return

    config = Config(elliptic_curve=args.curve)
    key = args.key.read().strip()
    if args.encrypt:
        plain_text = args.data.read()
        if isinstance(plain_text, str):
            plain_text = plain_text.encode()
        data = encrypt(key, plain_text, config)
        if args.out == sys.stdout:
            data = data.hex()
    elif args.decrypt:
        cipher_text = args.data.read()
        if isinstance(cipher_text, str):
            # if not bytes, suppose hex string
            cipher_text = bytes.fromhex(cipher_text.strip())
        data = decrypt(key, cipher_text, config)
        if args.out == sys.stdout:
            # if binary data, print hex; if not, print utf8
            data = readablize(data)
    else:
        raise NotImplementedError

    args.out.write(data)


if __name__ == "__main__":
    main()
