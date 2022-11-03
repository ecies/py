#!/bin/sh

# test
poetry run pip install coverage
poetry run python -m doctest -v ecies/utils.py
poetry run coverage run -m unittest discover .
poetry run coverage report
poetry run coverage xml

# test cli
poetry run eciespy -h
poetry run eciespy -g
echo '0x95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d' > prv
echo '0x98afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b' > pub
echo 'helloworld' | poetry run eciespy -e -k pub -O out
poetry run eciespy -d -k prv -D out
rm prv pub out
