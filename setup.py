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
import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
about = {}  # type: dict

with open(os.path.join(here, "ecies", "__version__.py"), "r") as f:
    exec(f.read(), about)

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name=about["__title__"],
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=about["__license__"],
    packages=find_packages(),
    install_requires=["eth-keys", "pysha3", "pycryptodomex", "coincurve"],
    entry_points={"console_scripts": ["eciespy = ecies.__main__:main"]},
    keywords=[
        "secp256k1",
        "crypto",
        "elliptic curves",
        "ecies",
        "bitcoin",
        "ethereum",
        "cryptocurrency",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security :: Cryptography",
    ],
)
