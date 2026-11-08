"""Geração e carga do certificado RSA autoassinado do servidor."""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

MIN_RSA_BITS = 2048


def generate_self_signed(common_name: str = "tp3-relay", bits: int = 2048,
                         days: int = 3650) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    if bits < MIN_RSA_BITS:
        raise ValueError(f"RSA com menos de {MIN_RSA_BITS} bits não é aceito")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                       # autoassinado
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def save_key(path: str, key: rsa.RSAPrivateKey) -> None:
    import os
    data = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # só o dono lê
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save_cert(path: str, cert: x509.Certificate) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("a chave do servidor deve ser RSA")
    if key.key_size < MIN_RSA_BITS:
        raise ValueError(f"chave RSA com {key.key_size} bits (mínimo {MIN_RSA_BITS})")
    return key


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def is_valid_now(cert: x509.Certificate) -> bool:
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        start = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        end = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return start <= now <= end


def key_matches_cert(key: rsa.RSAPrivateKey, cert: x509.Certificate) -> bool:
    pub = cert.public_key()
    return (isinstance(pub, rsa.RSAPublicKey)
            and pub.public_numbers() == key.public_key().public_numbers())
