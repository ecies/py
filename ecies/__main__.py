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
from ecies.utils import generate_key, to_eth_address, to_eth_public_key

__description__ = "Elliptic Curve Integrated Encryption Scheme for secp256k1 in Python"


def readablize(b: bytes) -> str:
    try:
        return b.decode()
    except ValueError:
        return b.hex()


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
        "-g", "--generate", action="store_true", help="generate ethereum key pair"
    )
    parser.add_argument(
        "-k", "--key", type=argparse.FileType("r"), help="public or private key file"
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
        k = generate_key()
        sk, pk, addr = (
            k.to_hex(),
            f"0x{to_eth_public_key(k.public_key).hex()}",
            to_eth_address(k.public_key),
        )
        print("Private: {}\nPublic: {}\nAddress: {}".format(sk, pk, addr))
        return

    if args.encrypt == args.decrypt:
        parser.print_help()
        return

    if not args.key:
        parser.print_help()
        return

    key = args.key.read().strip()
    if args.encrypt:
        plain_text = args.data.read()
        if isinstance(plain_text, str):
            plain_text = plain_text.encode()
        data = encrypt(key, plain_text)
        if args.out == sys.stdout:
            data = data.hex()
    else:
        cipher_text = args.data.read()
        if isinstance(cipher_text, str):
            # if not bytes, suppose hex string
            cipher_text = bytes.fromhex(cipher_text.strip())
        data = decrypt(key, cipher_text)
        if args.out == sys.stdout:
            # if binary data, print hex; if not, print utf8
            data = readablize(data)

    args.out.write(data)


if __name__ == "__main__":
    main()
