import os
import unittest

from coincurve import PrivateKey

from ecies import encrypt, decrypt
from ecies.utils import sha256, encapsulate, decapsulate, generate_eth_key, generate_key, aes_encrypt, aes_decrypt


class TestCrypt(unittest.TestCase):
    def setUp(self):
        self.test_string = b"this is a test"
        self.big_data = b"0" * 1024 * 1024 * 100  # 100 MB

    def test_hash(self):
        self.assertEqual(sha256(b"0" * 16).hex()[:8], "fcdb4b42")

    def test_hdkf(self):
        k1 = PrivateKey(secret=bytes([2]))
        self.assertEqual(k1.to_int(), 2)

        k2 = PrivateKey(secret=bytes([3]))
        self.assertEqual(k2.to_int(), 3)

        self.assertEqual(
            encapsulate(k1, k2.public_key), decapsulate(k1.public_key, k2)
        )
        self.assertEqual(
            encapsulate(k1, k2.public_key).hex(),
            '6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82'
        )

    def test_elliptic(self):
        data = self.test_string
        k = generate_eth_key()
        prvhex = k.to_hex()
        pubhex = k.public_key.to_hex()
        self.assertEqual(data, decrypt(prvhex, encrypt(pubhex, data)))

        k = generate_key()
        prvhex = k.to_hex()
        pubhex = k.public_key.format(False).hex()
        self.assertEqual(data, decrypt(prvhex, encrypt(pubhex, data)))
        self.assertEqual(data, decrypt(bytes.fromhex(prvhex), encrypt(bytes.fromhex(pubhex), data)))

        k = generate_key()
        prvhex = k.to_hex()
        pubhex = k.public_key.format(True).hex()
        self.assertEqual(data, decrypt(prvhex, encrypt(pubhex, data)))
        self.assertEqual(data, decrypt(bytes.fromhex(prvhex), encrypt(bytes.fromhex(pubhex), data)))

        self.assertRaises(TypeError, encrypt, 1, data)
        self.assertRaises(TypeError, decrypt, 1, encrypt(bytes.fromhex(pubhex), data))

    def test_aes(self):
        data = self.big_data
        key = os.urandom(16)
        self.assertEqual(data, aes_decrypt(key, aes_encrypt(key, data)))
