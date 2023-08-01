import os

from coincurve import PrivateKey

from ecies import ECIES_CONFIG
from ecies.utils import (
    decapsulate,
    decode_hex,
    encapsulate,
    sha256,
    sym_decrypt,
    sym_encrypt,
)
from ecies.utils.symmetric import derive_key


def __check_symmetric_random(data: bytes):
    key = os.urandom(32)
    sym_decrypt(key, sym_encrypt(key, data)) == data


def test_hash():
    assert sha256(b"0" * 16).hex()[:8] == "fcdb4b42"


def test_hkdf():
    derived = derive_key(b"secret").hex()
    assert derived == "2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf"


def test_encapsulate():
    k1 = PrivateKey(secret=bytes([2]))
    assert k1.to_int() == 2

    k2 = PrivateKey(secret=bytes([3]))
    assert k2.to_int() == 3

    assert encapsulate(k1, k2.public_key) == decapsulate(k1.public_key, k2)
    assert (
        encapsulate(k1, k2.public_key).hex()
        == "6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82"
    )


def test_aes():
    # test random
    __check_symmetric_random("helloworld🌍".encode())

    # test big
    data = b"1" * 1024 * 1024 * 100  # 100 MB
    __check_symmetric_random(data)

    # test known
    key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = decode_hex("0xf3e1ba810d2c8900b11312b7c725565f")
    tag = decode_hex("0Xec3b71e17c11dbe31484da9450edcf6c")
    encrypted = decode_hex("02d2ffed93b856f148b9")
    data = b"".join([nonce, tag, encrypted])
    assert b"helloworld" == sym_decrypt(key, data)


def test_xchacha20():
    ECIES_CONFIG.symmetric_algorithm = "xchacha20"

    # test random
    __check_symmetric_random("helloworld🌍".encode())

    # test big
    data = b"1" * 1024 * 1024 * 100  # 100 MB
    __check_symmetric_random(data)

    # test known
    key = decode_hex("27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828")
    nonce = decode_hex("0xfbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6")
    tag = decode_hex("0X5b5ccc27324af03b7ca92dd067ad6eb5")
    encrypted = decode_hex("aa0664f3c00a09d098bf")
    data = b"".join([nonce, tag, encrypted])
    assert b"helloworld" == sym_decrypt(key, data)

    ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
