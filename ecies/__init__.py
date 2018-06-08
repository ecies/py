
from ecies.utils import generate_key, hex2prv, hex2pub, derive, aes_encrypt, aes_decrypt

__all__ = ['encrypt', 'decrypt']


def encrypt(receiver_pubhex: str, msg: bytes) -> bytes:
    '''
    Encrypt with eth public key
    :param receiver_pubhex: eth pubc key hex, 64 bytes
    :param msg: raw bytes data to decrypt
    '''
    disposable_key = generate_key()
    receiver_pubkey = hex2pub(receiver_pubhex)
    aes_key = derive(disposable_key, receiver_pubkey)
    cipher_text = aes_encrypt(aes_key, msg)
    return disposable_key.public_key.format(False) + cipher_text


def decrypt(receiver_prvhex: str, msg: bytes) -> bytes:
    '''
    Decrypt with eth private key
    :param receiver_prvhex: eth private key hex
    :param msg: raw bytes data to decrypt
    '''
    pubkey = msg[0:65]  # pubkey's length is 65 bytes
    encrypted = msg[65:]
    sender_public_key = hex2pub(pubkey.hex())
    private_key = hex2prv(receiver_prvhex)
    aes_key = derive(private_key, sender_public_key)
    return aes_decrypt(aes_key, encrypted)
