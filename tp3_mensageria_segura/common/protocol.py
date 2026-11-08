"""Formatos de mensagem e constantes do protocolo (TP3 - Mensageria Segura E2E).

Todo frame na rede tem a forma:

    [ comprimento (4B, big-endian) ] [ tipo (1B) ] [ payload ... ]

O comprimento conta o byte de tipo + payload (ou seja, o que vem depois do
prefixo). Os tipos estão definidos abaixo.

Frame E2E (tipo T_E2E), payload:

    [ nonce (12B) ][ sender_id (16B) ][ recipient_id (16B) ][ seq_no (8B) ][ ciphertext+tag ]

    nonce = IV_base (4B) || seq_no (8B, big-endian)
    AAD   = sender_id || recipient_id || seq_no
"""
from __future__ import annotations

import uuid
from typing import NamedTuple

# ---------------------------------------------------------------- tamanhos
ID_LEN = 16        # client_id / sender_id / recipient_id (UUID v4 binário)
PK_LEN = 32        # chave pública X25519 (raw)
SALT_LEN = 16      # salt_srv
NONCE_LEN = 12     # AES-GCM
SEQ_LEN = 8        # seq_no (uint64 big-endian)
TAG_LEN = 16       # tag AES-GCM
KEY_LEN = 16       # AES-128
IV_BASE_LEN = 4
MAX_PLAINTEXT = 4096  # limite de texto claro por mensagem E2E

E2E_HEADER_LEN = NONCE_LEN + 2 * ID_LEN + SEQ_LEN        # 52
E2E_MIN_LEN = E2E_HEADER_LEN + TAG_LEN                   # 68  (texto vazio)
E2E_MAX_LEN = E2E_HEADER_LEN + MAX_PLAINTEXT + TAG_LEN   # 4164

# offsets dentro do payload E2E (o servidor só lê o recipient_id)
OFF_NONCE = 0
OFF_SENDER = NONCE_LEN                        # 12
OFF_RECIPIENT = NONCE_LEN + ID_LEN            # 28
OFF_SEQ = NONCE_LEN + 2 * ID_LEN              # 44
OFF_CT = E2E_HEADER_LEN                       # 52

# ---------------------------------------------------------------- tipos de frame
T_HELLO = 0x01          # cliente -> servidor (claro): client_id || pk_C
T_HELLO_REPLY = 0x02    # servidor -> cliente (claro, assinado): pk_S || salt || sig || cert

# Controle (cifrado/autenticado com as chaves C2S / S2C; payload = seq(8) || ct+tag)
T_REGISTER_ACK = 0x10   # servidor -> cliente
T_PEER_INFO = 0x11      # servidor -> cliente: client_id || pk || salt
T_PEER_LEAVE = 0x12     # servidor -> cliente: client_id
T_ERROR = 0x13          # servidor -> cliente: codigo(1) || detalhe
T_LIST_REQ = 0x14       # cliente -> servidor
T_BYE = 0x15            # cliente -> servidor

T_E2E = 0x20            # cliente <-> servidor <-> cliente (relay)

CONTROL_S2C = (T_REGISTER_ACK, T_PEER_INFO, T_PEER_LEAVE, T_ERROR)
CONTROL_C2S = (T_LIST_REQ, T_BYE)

# ---------------------------------------------------------------- códigos de erro (T_ERROR)
ERR_DUPLICATE_ID = 1
ERR_RECIPIENT_OFFLINE = 2   # detalhe = recipient_id (16B)
ERR_BAD_SENDER = 3
ERR_BAD_FRAME = 4
ERR_SERVER_FULL = 5

ERROR_TEXT = {
    ERR_DUPLICATE_ID: "client_id já está em uso por outra conexão",
    ERR_RECIPIENT_OFFLINE: "destinatário não está conectado",
    ERR_BAD_SENDER: "sender_id do frame não corresponde ao client_id autenticado",
    ERR_BAD_FRAME: "frame inválido",
    ERR_SERVER_FULL: "servidor sem capacidade",
}


class ProtocolError(Exception):
    """Violação do formato do protocolo."""


# ---------------------------------------------------------------- utilidades
def check_uuid4(client_id: bytes) -> None:
    """Garante que client_id é um UUID v4 de 16 bytes."""
    if len(client_id) != ID_LEN:
        raise ProtocolError("client_id deve ter 16 bytes")
    u = uuid.UUID(bytes=client_id)
    if u.version != 4 or u.variant != uuid.RFC_4122:
        raise ProtocolError("client_id não é um UUID v4")


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise ProtocolError(msg)


# ---------------------------------------------------------------- HELLO
def pack_hello(client_id: bytes, pk_c: bytes) -> bytes:
    _need(len(client_id) == ID_LEN and len(pk_c) == PK_LEN, "HELLO com tamanhos inválidos")
    return client_id + pk_c


def parse_hello(payload: bytes) -> tuple[bytes, bytes]:
    _need(len(payload) == ID_LEN + PK_LEN, "HELLO com tamanho inválido")
    return payload[:ID_LEN], payload[ID_LEN:]


# ---------------------------------------------------------------- HELLO_REPLY
class HelloReply(NamedTuple):
    pk_s: bytes
    salt: bytes
    signature: bytes
    cert_der: bytes


def pack_hello_reply(pk_s: bytes, salt: bytes, signature: bytes, cert_der: bytes) -> bytes:
    _need(len(pk_s) == PK_LEN and len(salt) == SALT_LEN, "HELLO_REPLY com tamanhos inválidos")
    _need(len(signature) < 65536 and len(cert_der) < 65536, "assinatura/certificado grandes demais")
    return (pk_s + salt
            + len(signature).to_bytes(2, "big") + signature
            + len(cert_der).to_bytes(2, "big") + cert_der)


def parse_hello_reply(payload: bytes) -> HelloReply:
    fixed = PK_LEN + SALT_LEN
    _need(len(payload) >= fixed + 2, "HELLO_REPLY curto demais")
    pk_s = payload[:PK_LEN]
    salt = payload[PK_LEN:fixed]
    off = fixed
    sig_len = int.from_bytes(payload[off:off + 2], "big")
    off += 2
    _need(len(payload) >= off + sig_len + 2, "HELLO_REPLY truncado (assinatura)")
    sig = payload[off:off + sig_len]
    off += sig_len
    cert_len = int.from_bytes(payload[off:off + 2], "big")
    off += 2
    _need(len(payload) == off + cert_len, "HELLO_REPLY com tamanho inconsistente (certificado)")
    cert = payload[off:off + cert_len]
    _need(sig_len > 0 and cert_len > 0, "HELLO_REPLY sem assinatura ou certificado")
    return HelloReply(pk_s, salt, sig, cert)


# ---------------------------------------------------------------- PEER_INFO / PEER_LEAVE / ERROR
class PeerInfo(NamedTuple):
    client_id: bytes
    public_key: bytes
    salt: bytes


def pack_peer_info(client_id: bytes, pk: bytes, salt: bytes) -> bytes:
    return client_id + pk + salt


def parse_peer_info(plain: bytes) -> PeerInfo:
    _need(len(plain) == ID_LEN + PK_LEN + SALT_LEN, "PEER_INFO com tamanho inválido")
    return PeerInfo(plain[:ID_LEN], plain[ID_LEN:ID_LEN + PK_LEN], plain[ID_LEN + PK_LEN:])


def parse_peer_leave(plain: bytes) -> bytes:
    _need(len(plain) == ID_LEN, "PEER_LEAVE com tamanho inválido")
    return plain


def pack_error(code: int, detail: bytes = b"") -> bytes:
    return bytes([code]) + detail


def parse_error(plain: bytes) -> tuple[int, bytes]:
    _need(len(plain) >= 1, "ERROR vazio")
    return plain[0], plain[1:]


# ---------------------------------------------------------------- frame E2E
class E2EFrame(NamedTuple):
    nonce: bytes
    sender_id: bytes
    recipient_id: bytes
    seq_bytes: bytes
    ciphertext: bytes   # ciphertext || tag

    @property
    def seq_no(self) -> int:
        return int.from_bytes(self.seq_bytes, "big")

    @property
    def aad(self) -> bytes:
        return e2e_aad(self.sender_id, self.recipient_id, self.seq_bytes)


def e2e_aad(sender_id: bytes, recipient_id: bytes, seq_bytes: bytes) -> bytes:
    """AAD do AES-GCM: sender_id | recipient_id | seq_no."""
    return sender_id + recipient_id + seq_bytes


def pack_e2e(nonce: bytes, sender_id: bytes, recipient_id: bytes,
             seq_bytes: bytes, ct_and_tag: bytes) -> bytes:
    return nonce + sender_id + recipient_id + seq_bytes + ct_and_tag


def parse_e2e(payload: bytes) -> E2EFrame:
    _need(E2E_MIN_LEN <= len(payload) <= E2E_MAX_LEN, "frame E2E com tamanho inválido")
    return E2EFrame(
        payload[OFF_NONCE:OFF_SENDER],
        payload[OFF_SENDER:OFF_RECIPIENT],
        payload[OFF_RECIPIENT:OFF_SEQ],
        payload[OFF_SEQ:OFF_CT],
        payload[OFF_CT:],
    )
