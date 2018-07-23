import os
import unittest

from ecies import encrypt, decrypt
from ecies.utils import sha256, generate_eth_key, aes_encrypt, aes_decrypt


class TestCrypt(unittest.TestCase):
    def setUp(self):
        self.test_string = b"this is a test"
        self.big_data = b"0" * 1024 * 1024 * 100  # 100 MB

    def test_hash(self):
        self.assertEqual(sha256(b"0" * 16).hex()[:8], "fcdb4b42")

    def test_elliptic(self):
        data = self.test_string
        k = generate_eth_key()
        prvhex = k.to_hex()
        pubhex = k.public_key.to_hex()
        self.assertEqual(data, decrypt(prvhex, encrypt(pubhex, data)))

    def test_aes(self):
        data = self.big_data
        key = os.urandom(16)
        self.assertEqual(data, aes_decrypt(key, aes_encrypt(key, data)))
