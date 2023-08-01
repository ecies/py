from dataclasses import dataclass
from typing import Literal

SymmetricAlgorithm = Literal["aes-256-gcm", "xchacha20"]
NonceLength = Literal[12, 16]  # only for aes-256-gcm, xchacha20 will always be 24

COMPRESSED_PUBLIC_KEY_SIZE = 33
UNCOMPRESSED_PUBLIC_KEY_SIZE = 65


@dataclass()
class Config:
    is_ephemeral_key_compressed: bool = False
    is_hkdf_key_compressed: bool = False
    symmetric_algorithm: SymmetricAlgorithm = "aes-256-gcm"
    symmetric_nonce_length: NonceLength = 16

    @property
    def ephemeral_key_size(self):
        return (
            COMPRESSED_PUBLIC_KEY_SIZE
            if self.is_ephemeral_key_compressed
            else UNCOMPRESSED_PUBLIC_KEY_SIZE
        )


ECIES_CONFIG = Config()
