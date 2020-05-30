"""
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

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

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
        k = generate_eth_key()
        prv, pub, addr = (
            k.to_hex(),
            k.public_key.to_hex(),
            k.public_key.to_checksum_address(),
        )
        print("Private: {}\nPublic: {}\nAddress: {}".format(prv, pub, addr))
        return

    if args.encrypt == args.decrypt:
        parser.print_help()
        return

    if not args.key:
        parser.print_help()
        return

    key = args.key.read().strip()
    if args.encrypt:
        plaintext = args.data.read()
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        data = encrypt(key, plaintext)
        if args.out == sys.stdout:
            data = data.hex()
    else:
        ciphertext = args.data.read()
        if isinstance(ciphertext, str):
            # if not bytes, suppose hex string
            ciphertext = bytes.fromhex(ciphertext.strip())
        data = decrypt(key, ciphertext)
        if args.out == sys.stdout:
            # if binary data, print hex; if not, print utf8
            data = readablize(data)

    args.out.write(data)


if __name__ == "__main__":
    main()
