"""Primitivas criptográficas usadas pelo protocolo.

- X25519 (ECDHE) com chaves públicas em formato raw de 32 bytes
- HKDF-SHA256 (Extract e Expand implementados explicitamente, RFC 5869)
- AES-128-GCM (AEAD); a tag de 16 bytes fica concatenada ao ciphertext
- RSA-PSS (SHA-256) para a assinatura do handshake

Nada aqui registra logs: este módulo manipula segredos.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .protocol import ID_LEN, IV_BASE_LEN, KEY_LEN, NONCE_LEN, PK_LEN, SALT_LEN, SEQ_LEN

_HASH_LEN = 32  # SHA-256


class CryptoError(Exception):
    """Falha criptográfica (chave inválida, parâmetros incorretos...)."""


class AuthenticationError(CryptoError):
    """A tag de autenticação do AES-GCM não confere."""


# ------------------------------------------------------------------ X25519
def generate_x25519() -> tuple[X25519PrivateKey, bytes]:
    """Gera um par efêmero. Retorna (sk, pk_raw_32B). A sk NUNCA deve ser enviada."""
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk


def x25519_exchange(sk: X25519PrivateKey, pk_peer: bytes) -> bytes:
    """Z = ECDH(sk, pk_peer). Rejeita chaves de tamanho errado e pontos de ordem baixa."""
    if len(pk_peer) != PK_LEN:
        raise CryptoError("chave pública X25519 deve ter 32 bytes")
    try:
        z = sk.exchange(X25519PublicKey.from_public_bytes(pk_peer))
    except ValueError as exc:
        raise CryptoError("chave pública X25519 inválida") from exc
    if hmac.compare_digest(z, bytes(PK_LEN)):
        raise CryptoError("segredo compartilhado nulo (ponto de ordem baixa)")
    return z


# ------------------------------------------------------------------ HKDF (RFC 5869)
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """PRK = HMAC-SHA256(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """OKM = T(1) || T(2) || ... truncado em `length` bytes."""
    if length <= 0 or length > 255 * _HASH_LEN:
        raise CryptoError("tamanho de saída do HKDF inválido")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ------------------------------------------------------------------ AES-128-GCM
def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Retorna ciphertext || tag(16B)."""
    if len(key) != KEY_LEN or len(nonce) != NONCE_LEN:
        raise CryptoError("chave deve ter 16 bytes e nonce 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
    """Decifra e verifica a tag. Levanta AuthenticationError se algo foi alterado."""
    if len(key) != KEY_LEN or len(nonce) != NONCE_LEN:
        raise CryptoError("chave deve ter 16 bytes e nonce 12 bytes")
    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag as exc:
        raise AuthenticationError("tag GCM inválida") from exc


def make_nonce(prefix4: bytes, seq_no: int) -> bytes:
    """nonce (12B) = prefix (4B) || seq_no (8B, big-endian).

    No E2E o prefixo é o IV_base aleatório da sessão/direção; no canal de
    controle é a direção (0 = c2s, 1 = s2c).
    """
    if len(prefix4) != IV_BASE_LEN:
        raise CryptoError("prefixo do nonce deve ter 4 bytes")
    if not 0 <= seq_no < 2 ** 64:
        raise CryptoError("seq_no fora do intervalo de 64 bits")
    return prefix4 + seq_no.to_bytes(SEQ_LEN, "big")


# ------------------------------------------------------------------ RSA-PSS
def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=_HASH_LEN)


def handshake_hash(pk_s: bytes, pk_c: bytes, client_id: bytes, salt: bytes) -> bytes:
    """H = SHA256(pk_S || pk_C || client_id || salt)  (todos em bytes crus)."""
    if (len(pk_s), len(pk_c), len(client_id), len(salt)) != (PK_LEN, PK_LEN, ID_LEN, SALT_LEN):
        raise CryptoError("tamanhos inválidos no material do handshake")
    return hashlib.sha256(pk_s + pk_c + client_id + salt).digest()


def rsa_pss_sign(private_key: rsa.RSAPrivateKey, digest_h: bytes) -> bytes:
    """Assina H (já é um digest SHA-256) com RSA-PSS(SHA-256, salt=32B)."""
    return private_key.sign(digest_h, _pss(), Prehashed(hashes.SHA256()))


def rsa_pss_verify(public_key: rsa.RSAPublicKey, signature: bytes, digest_h: bytes) -> bool:
    try:
        public_key.verify(signature, digest_h, _pss(), Prehashed(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------ utilidades
def fingerprint(public_key_raw: bytes) -> str:
    """Impressão digital curta (SHA-256 truncado) para log/comparação fora do canal."""
    d = hashlib.sha256(public_key_raw).hexdigest()[:16]
    return " ".join(d[i:i + 4] for i in range(0, 16, 4))
