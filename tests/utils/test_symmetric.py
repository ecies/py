import os

import pytest

from ecies.config import SymmetricAlgorithm
from ecies.utils import decode_hex, sym_decrypt, sym_encrypt


def __check_symmetric_random(
    data: bytes, algorithm: SymmetricAlgorithm = "aes-256-gcm"
):
    key = os.urandom(32)
    sym_decrypt(key, sym_encrypt(key, data, algorithm), algorithm) == data


@pytest.mark.parametrize("algorithm", ["aes-256-gcm", "xchacha20"])
def test_symmetric_random(data, algorithm):
    __check_symmetric_random(data, algorithm)


@pytest.mark.parametrize("algorithm", ["aes-256-gcm", "xchacha20"])
def test_symmetric_big(algorithm, big_data):
    __check_symmetric_random(big_data, algorithm)


def test_aes_known():
    key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = decode_hex("0xf3e1ba810d2c8900b11312b7c725565f")
    tag = decode_hex("0Xec3b71e17c11dbe31484da9450edcf6c")
    encrypted = decode_hex("02d2ffed93b856f148b9")
    data = b"".join([nonce, tag, encrypted])
    assert b"helloworld" == sym_decrypt(key, data)


def test_xchacha20_known():
    key = decode_hex("27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828")
    nonce = decode_hex("0xfbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6")
    tag = decode_hex("0X5b5ccc27324af03b7ca92dd067ad6eb5")
    encrypted = decode_hex("aa0664f3c00a09d098bf")
    data = b"".join([nonce, tag, encrypted])
    assert b"helloworld" == sym_decrypt(key, data, "xchacha20")
