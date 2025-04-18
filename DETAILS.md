# Mechanism and implementation

This library combines `secp256k1` and `AES-256-GCM` (powered by [`coincurve`](https://github.com/ofek/coincurve) and [`pycryptodome`](https://github.com/Legrandin/pycryptodome)) to provide an API of encrypting with `secp256k1` public key and decrypting with `secp256k1`'s private key. It has two parts generally:

1. Use [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman) to exchange an AES session key;

   > Notice that the sender public key is generated every time when `ecies.encrypt` is invoked, thus, the AES session key varies.
   >
   > We are using HKDF-SHA256 instead of SHA256 to derive the AES keys.

2. Use this AES session key to encrypt/decrypt the data under `AES-256-GCM`.

Basically the encrypted data will be like this:

```plaintext
+-------------------------------+----------+----------+-----------------+
| 65 Bytes                      | 16 Bytes | 16 Bytes | == data size    |
+-------------------------------+----------+----------+-----------------+
| Sender Public Key (ephemeral) | Nonce/IV | Tag/MAC  | Encrypted data  |
+-------------------------------+----------+----------+-----------------+
| sender_pk                     | nonce    | tag      | encrypted_data  |
+-------------------------------+----------+----------+-----------------+
|           Secp256k1           |              AES-256-GCM              |
+-------------------------------+---------------------------------------+
```

## Secp256k1

### Glance at ECDH

So, **how** do we calculate the ECDH key under `secp256k1`? If you use a library like [`coincurve`](https://github.com/ofek/coincurve), you might just simply call `k1.ecdh(k2.public_key.format())`, then uh-huh, you got it! Let's see how to do it in simple Python snippets:

```python
>>> from coincurve import PrivateKey
>>> k1 = PrivateKey.from_int(3)
>>> k2 = PrivateKey.from_int(2)
>>> k1.public_key.format(False).hex() # 65 bytes, False means uncompressed key
'04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'
>>> k2.public_key.format(False).hex() # 65 bytes
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
>>> k1.ecdh(k2.public_key.format()).hex()
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
>>> k2.ecdh(k1.public_key.format()).hex()
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
```

### Calculate your ecdh key manually

However, as a hacker like you with strong desire to learn something, you must be curious about the magic under the ground.

In one sentence, the `secp256k1`'s ECDH key of `k1` and `k2` is nothing but `sha256(k2.public_key.multiply(k1))`.

```python
>>> k1.to_int()
3
>>> shared = k2.public_key.multiply(k1.secret)
>>> shared.point()
(115780575977492633039504758427830329241728645270042306223540962614150928364886,
 78735063515800386211891312544505775871260717697865196436804966483607426560663)
>>> import hashlib
>>> h = hashlib.sha256()
>>> h.update(shared.format())
>>> h.hexdigest()  # here you got the ecdh key same as above!
'c7d9ba2fa1496c81be20038e5c608f2fd5d0246d8643783730df6c2bbb855cb2'
```

> Warning: **NEVER** use small integers as private keys on any production systems or storing any valuable assets.
>
> Warning: **ALWAYS** use safe methods like [`os.urandom`](https://docs.python.org/3/library/os.html#os.urandom) to generate private keys.

### Math on ecdh

Let's discuss in details. The word _multiply_ here means multiplying a **point** of a public key on elliptic curve (like `(x, y)`) with a **scalar** (like `k`). Here `k` is the integer format of a private key, for instance, it can be `3` for `k1` here, and `(x, y)` here is an extremely large number pair like `(115780575977492633039504758427830329241728645270042306223540962614150928364886, 78735063515800386211891312544505775871260717697865196436804966483607426560663)`.

> Warning: 1 \* (x, y) == (x, y) is always true, since 1 is the **identity element** for multiplication. If you take integer 1 as a private key, the public key will be the [base point](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm).

Mathematically, the elliptic curve cryptography is based on the fact that you can easily multiply point `A` (aka base point, or public key in ECDH) and scalar `k` (aka private key) to get another point `B` (aka public key), but it's almost impossible to calculate `A` from `B` reversely (which means it's a "one-way function").

### Compressed and uncompressed keys

A point multiplying a scalar can be regarded that this point adds itself multiple times, and the point `B` can be converted to a readable public key in a compressed or uncompressed format.

- Compressed format (`x` coordinate only)

```python
>>> point = (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
>>> point == k2.public_key.point()
True
>>> prefix = '02' if point[1] % 2 == 0 else '03'
>>> compressed_key_hex = prefix + hex(point[0])[2:]
>>> compressed_key = bytes.fromhex(compressed_key_hex)
>>> compressed_key.hex()
'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
```

- Uncompressed format (`(x, y)` coordinate)

```python
>>> uncompressed_key_hex = '04' + hex(point[0])[2:] + hex(point[1])[2:]
>>> uncompressed_key = bytes.fromhex(uncompressed_key_hex)
>>> uncompressed_key.hex()
'04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a'
```

The format is depicted by the image below from the [bitcoin book](https://github.com/bitcoinbook/bitcoinbook).

![EC public key format](https://raw.githubusercontent.com/bitcoinbook/bitcoinbook/develop/images/mbc3_0408.png)

> If you want to convert the compressed format to uncompressed, basically, you need to calculate `y` from `x` by solving the equation using [Cipolla's Algorithm](https://en.wikipedia.org/wiki/Cipolla's_algorithm):
>
> ![y^2=(x^3 + 7) mod p, where p=2^{256}-2^{32}-2^{9}-2^{8}-2^{7}-2^{6}-2^{4}-1](<https://tex.s2cms.ru/svg/%20y%5E2%3D(x%5E3%20%2B%207)%20%5Cbmod%20p%2C%5C%20where%5C%20p%3D2%5E%7B256%7D-2%5E%7B32%7D-2%5E%7B9%7D-2%5E%7B8%7D-2%5E%7B7%7D-2%5E%7B6%7D-2%5E%7B4%7D-1%20>)
>
> You can check the [bitcoin wiki](https://en.bitcoin.it/wiki/Secp256k1) and this thread on [bitcointalk.org](https://bitcointalk.org/index.php?topic=644919.msg7205689#msg7205689) for more details.

Then, the shared key between `k1` and `k2` is the `sha256` hash of the **compressed** ECDH public key. It's better to use the compressed format, since you can always get `x` from `x` or `(x, y)` without any calculation.

You may want to ask, what if we don't hash it? Briefly, hash can:

1. Make the shared key's length fixed;
2. Make it safer since hash functions can remove "weak bits" in the original computed key. Check the introduction section of this [paper](http://cacr.uwaterloo.ca/techreports/1998/corr98-05.pdf) for more details.

> Warning: According to some recent research, although widely used, the `sha256` key derivation function is [not secure enough](https://github.com/ecies/py/issues/82).

## AES

Now we have the shared key, and we can use the `nonce` and `tag` to decrypt. This is quite straight, and the example derives from `pycryptodome`'s [documentation](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes).

```python
>>> from Crypto.Cipher import AES
>>> key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> nonce = b'\xf3\xe1\xba\x81\r,\x89\x00\xb1\x13\x12\xb7\xc7%V_'
>>> tag = b'\xec;q\xe1|\x11\xdb\xe3\x14\x84\xda\x94P\xed\xcfl'
>>> data = b'\x02\xd2\xff\xed\x93\xb8V\xf1H\xb9'
>>> decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
>>> decipher.decrypt_and_verify(data, tag)
b'helloworld'
```

> Strictly speaking, `nonce` != `iv`, but this is a little bit off topic, if you are curious, you can check [the comment in `utils/symmetric.py`](./ecies/utils/symmetric.py#L83).
>
> Warning: it's dangerous to reuse nonce, if you don't know what you are doing, just follow the default setting.
