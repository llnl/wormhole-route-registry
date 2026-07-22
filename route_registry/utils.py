import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key as rsa_generate_private_key,
    RSAPublicKey,
    RSAPrivateKey,
)
from cryptography.hazmat.primitives import serialization
from secrets import token_urlsafe
from urllib.parse import urljoin as lib_urljoin


def make_token(nbytes: int = 32) -> str:
    return token_urlsafe(nbytes)


def generate_private_key(exponent: int = 65537, key_size: int = 2048) -> RSAPrivateKey:
    return rsa_generate_private_key(public_exponent=exponent, key_size=key_size)


def generate_public_key(private_key: RSAPrivateKey) -> RSAPublicKey:
    return private_key.public_key()


def convert_private_key_to_pem(private_key: RSAPrivateKey) -> bytes:
    # TODO: configurable options, etc
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def convert_public_key_to_pem(public_key: RSAPublicKey) -> bytes:
    # TODO: configurable options, etc
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_kid(public_key: RSAPublicKey) -> bytes:
    # TODO: configurable options, etc
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha256 = hashlib.sha256(public_der).digest()
    return base64.urlsafe_b64encode(sha256).rstrip(b"=")


def urljoin(base: str, path: str, replace: bool = False, **kwargs) -> str:
    """Join a URL with another path.

    Makes the behavior of `urllib.parse.urljoin` more explicit by requiring
    the caller to specify whether or not to replace the entire base path.
    """
    if replace:
        base = base.rstrip("/")
        path = path if path[0] == "/" else f"/{path}"
    else:
        base = base if base[-1] == "/" else f"{base}/"
        path = path.lstrip("/")

    return lib_urljoin(base, path, **kwargs)
