"""
Server module intended for runtime.

DL-JWTSERVER,
by hereticSibyl, sibyl@dreamerslegacy.xyz

A light-weight JWT authentication server.
"""
import configparser
from os.path import isfile
from os import remove
from typing import List, Literal, Optional, Union
from base64 import b64decode, b64encode
from random import choice
from string import ascii_letters
from ast import literal_eval
from time import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature, InvalidKey
from tinydb import TinyDB, where
from flask import Flask, request
from flask_restful import Resource, Api


if not isfile("keys/private.pem"):
    private = rsa.generate_private_key(65537, 4096)
    with open("keys/private.pem", "wb") as private_key_handler:
        private_key_handler.write(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    remove("keys/public.pem")
else:
    with open("keys/private.pem", "wb") as private_key_handler:
        private = serialization.load_pem_private_key(  # type: ignore
            private_key_handler.read(), None)
        assert isinstance(private, rsa.RSAPrivateKey)

if not isfile("keys/public.pem"):
    with open("keys/public.pem", "wb") as public_key_handler:
        public_key_handler.write(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

if not isfile("keys/salt"):
    salt = "".join([choice(ascii_letters) for _ in range(128)])
    with open("keys/salt", "w") as salt_handler:
        salt_handler.write(salt)
else:
    with open("keys/salt") as salt_handler:
        salt = salt_handler.read()

database = TinyDB("db.json")

config = configparser.ConfigParser()
config.read("main.cfg")

app = Flask(__name__)
api = Api(app)

DATABASE_KEY_LOOKUP = {
    "username": str,
    "email": str,
    "ed25519": str,
    "password": str
}


class AuthProcessor:
    """Class for authentication processing."""

    class AuthResult:
        """Object representing the result of authentication processing."""

        def __init__(self, successful: bool, error: Optional[str] = None):
            """Initialize authentication result."""
            self.successful: bool = successful
            self.error: Optional[str] = error

    def __init__(self, username: str, answer: str,
                 mode: Literal["ed25519", "password"]):
        """
        Initialize and execute authentication processor.

        :param username: username of the user for authentication to be
            processed
        :type username: str
        :param answer: provided solution to the authentication challenge
        :type answer: str
        :param mode: authentication type to be processed as
        :type mode: str
        """
        self.username: str = username
        self.answer: str = answer
        record: List[dict] = database.search(
            where("username") == self.username)
        if not record:
            raise ValueError("User does not exist!")
        self.record: dict = record.pop()
        self.mode: str = mode
        if self.mode == "ed25519":
            if "ed25519key" not in self.record.keys():
                self.result = AuthProcessor.AuthResult(
                    False, "User has no ed25519 key.")
            else:
                try:
                    key: ed25519.Ed25519PublicKey = \
                        serialization.load_pem_public_key(  # type: ignore
                            self.record["ed25519key"].encode())
                    if not isinstance(key, ed25519.Ed25519PublicKey):
                        raise InvalidKey()
                    try:
                        key.verify(b64decode(self.answer.encode()), b"SIGNME")
                        self.result = AuthProcessor.AuthResult(True)
                    except InvalidSignature:
                        self.result = AuthProcessor.AuthResult(
                            False, "ed25519 signature invalid.")
                except InvalidKey:
                    self.result = AuthProcessor.AuthResult(
                        False, "Unable to import user's ed25519 key. Please "
                        "use another authentication mechanism, or contact "
                        "server administrator(s).")
        elif self.mode == "password":
            if "password" not in self.record.keys():
                self.result = AuthProcessor.AuthResult(
                    False, "User has no password.")
            else:
                digest = hashes.Hash(hashes.SHA3_512())
                digest.update((answer + salt).encode())
                if self.record["password"] == \
                        b64encode(digest.finalize()).decode():
                    self.result = AuthProcessor.AuthResult(True)
                else:
                    self.result = AuthProcessor.AuthResult(
                        False, "Password incorrect.")

    def create_jwt(self) -> str:
        """Create JSON Web Token for use by user in authentication."""
        return jwt.encode(
            {
                "iss": literal_eval(config["claim"]["iss"]),
                "sub": literal_eval(config["claim"]["sub"]),
                "exp": literal_eval(config["claim"]["exp"]) + time(),
                "preferred_username": self.username,
                "email": self.record["email"],
                "email_verified": False
            },
            private.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode(),
            algorithm="RS256")


class Auth(Resource):
    """Object representation of authentication resource."""

    def _retrieve_request_data(self) -> Union[str, dict]:
        """
        Retrieve safely JSON data from the request.

        :return: JSON data as dictionary, or error string
        :rtype: Union[str, dict]
        """
        arguments = request.get_json()
        try:
            assert arguments is not None
        except AssertionError:
            return "Missing arguments required to process request."
        return arguments

    @staticmethod
    def _auth_password_process(password: str) -> str:
        """
        Convert plain-text password to Base64-encoded hash, made with the \
            server's generated salt.

        :param password: plain-text password
        :type password: str
        :return: Base64-encoded hash
        :rtype: str
        """
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update((password + salt).encode())
        return b64encode(digest.finalize()).decode()

    @staticmethod
    def _auth_ed25519_process(pem_key: str) -> Optional[str]:
        """
        Check given key, then returns error string if invalid.

        :param pem_key: PEM-formatted public key, supposedly ED25519
        :type pem_key: str
        :return: optionally error string if invalid
        :rtype: Optional[str]
        """
        try:
            if not isinstance(serialization.load_pem_public_key(
                    pem_key.encode()), ed25519.Ed25519PublicKey):
                raise InvalidKey()
        except InvalidKey:
            return "Arguments includes an invalid key."
        return None

    def get(self, username: str):
        """
        Respond to resource GET requests.

        Return JWT if given proper authentication, or error message if given \
            missing, invalid, or malformed authentication.
        """
        data = self._retrieve_request_data()
        if isinstance(data, str):
            return {"error": data}, 400
        try:
            assert data["mode"] in ["ed25519", "password"]
            authenticator = AuthProcessor(username, str(data["answer"]),
                                          data["mode"])
            if authenticator.result.successful is False:
                if authenticator.result.error:
                    return {"error": authenticator.result.error}, 401
                return {"error": "Authentication failed with an unspecified "
                        "error."}, 401
        except AssertionError:
            return {"error": "Invalid authentication mode."}, 400
        except KeyError:
            return {"error": "Missing arguments required to process request."},
            400
        except ValueError:
            return {"error": "User does not exist."}, 404
        return {"jwt": authenticator.create_jwt()}, 200

    def put(self, username: str):
        """
        Respond to resource PUT requests.

        Return code 201 if given proper parameters, or error message if given \
            missing, invalid, or malformed parameters.
        """
        data = self._retrieve_request_data()
        if isinstance(data, str):
            return {"errors": data}, 400
        if "email" not in data:
            data["email"] = "user@0.0.0.0"
        try:
            assert not database.search(where("username") == username)
            new_user = {
                "username": username,
                "email": str(data["email"]),
            }
            if "password" in data:
                new_user.update({
                    "password": self._auth_password_process(
                        str(data["password"]))
                })
            if "ed25519key" in data:
                check = self._auth_ed25519_process(str(data["ed25519key"]))
                if check:
                    return {"error": check}, 400
                new_user.update({
                    "ed25519key": str(data["ed25519key"])
                })
            database.insert(new_user)
        except AssertionError:
            return {"error": "User already exists."}, 409
        except KeyError:
            return {"error": "Missing arguments required to process request."},
            400
        return {"info": "User " + username + " successfully created."}, 201

    def delete(self, username: str):
        """
        Respond to resource DELETE requests.

        Return code 200 if given proper authentication, or error message if \
            given missing, invalid, or malformed authentication.
        """
        data = self._retrieve_request_data()
        if isinstance(data, str):
            return {"error": data}, 400
        try:
            assert data["mode"] in ["ed25519", "password"]
            authenticator = AuthProcessor(username, str(data["answer"]),
                                          data["mode"])
            if authenticator.result.successful is False:
                if authenticator.result.error:
                    return {"error": authenticator.result.error}, 401
                return {"error": "Authentication failed with an unspecified "
                        "error."}, 401
        except AssertionError:
            return {"error": "Invalid authentication mode."}, 400
        except KeyError:
            return {"error": "Missing arguments required to process request."},
            400
        except ValueError:
            return {"error": "User does not exist."}, 404
        database.remove(where("username") == username)
        return {"info": "User " + username + " successfully deleted."}, 200

    def patch(self, username: str):
        """
        Respond to resource PATCH requests.

        Return code 200 if given proper authentication, or error message if \
            given missing invalid or malformed authentication, and given \
                proper parameters, or error message if given missing, \
                    invalid, or malformed parameters.
        """
        data = self._retrieve_request_data()
        if isinstance(data, str):
            return {"error": data}, 400
        try:
            assert data["mode"] in ["ed25519", "password"]
            authenticator = AuthProcessor(username, str(data["answer"]),
                                          data["mode"])
            if authenticator.result.successful is False:
                if authenticator.result.error:
                    return {"error": authenticator.result.error}, 401
                return {"error": "Authentication failed with an unspecified "
                        "error."}, 401
        except AssertionError:
            return {"error": "Invalid authentication mode."}, 400
        except KeyError:
            return {"error": "Missing arguments required to process request."},
            400
        except ValueError:
            return {"error": "User does not exist."}, 404
        invalid_keys = []
        for key in data["new"]:
            if key in DATABASE_KEY_LOOKUP:
                if isinstance(data["new"][key], DATABASE_KEY_LOOKUP[key]):
                    if key == "ed25519key":
                        check = self._auth_ed25519_process(data["new"][key])
                        if check:
                            return {"error": check}, 400
                    elif key == "password":
                        data["new"][key] = self._auth_password_process(
                            data["new"][key])
                else:
                    return {"error",
                            "Argument " + key + " is of invalid type."}
            else:
                invalid_keys.append(key)
        for key in invalid_keys:
            data["new"].pop(key)
        database.update(data["new"], where("username") == username)
        return {"info": "User " + username + " successfully updated."}, 200


api.add_resource(Auth, "/claims/<string:username>")

if __name__ == "__main__":
    app.run(debug=True)
