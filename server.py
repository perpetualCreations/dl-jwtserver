"""
Server module intended for runtime.

DL-JWTSERVER,
by hereticSibyl, sibyl@dreamerslegacy.xyz

A light-weight JWT authentication server.
"""
from os.path import isfile
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from tinydb import TinyDB, Query


if not isfile("keys/private.pem"):
    private = rsa.generate_private_key(65537, 4096)
    with open("keys/private.pem", "wb") as private_key_handler:
        private_key_handler.write(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
else:
    with open("keys/private.pem", "wb") as private_key_handler:
        private = serialization.load_pem_private_key(  # type: ignore
            private_key_handler.read(), None)
        assert isinstance(private, rsa.RSAPrivateKey)
public = private.public_key()

database = TinyDB("db.json")
