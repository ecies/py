#!/bin/sh

# test cli
poetry run eciespy -h

# test encrypt/decrypt
## secp256k1
poetry run eciespy -g
echo '0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d' > sk
echo '0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b' > pk
echo 'hello world 🌍' | poetry run eciespy -e -k pk -O out
poetry run eciespy -d -k sk -D out

## x25519
poetry run eciespy -g -c x25519
echo '0xe2bfe58d930bd4cb367498fdf5f3df33967d03a691b565360f6265604503748e' > sk
echo '0x94cb092f6b68b4df6bbb0d5f3de01f95cb89f25e24d6cf89bba34de71d9da74e' > pk
echo 'hello world (x25519) 🌍' | poetry run eciespy -e -k pk -O out -c x25519
poetry run eciespy -d -k sk -D out -c x25519

## ed25519
poetry run eciespy -g -c ed25519
echo '0x94faa19c13ab8dddbd0b0a869473dc35c29790b2dd01923f5aefccfbe3657053' > sk
echo '0x204c4e77a8c506e030f0209fbeca147068c33eef05affd11ea2b04afaaeec74b' > pk
echo 'hello world (ed25519) 🌍' | poetry run eciespy -e -k pk -O out -c ed25519
poetry run eciespy -d -k sk -D out -c ed25519

# cleanup
rm sk pk out
