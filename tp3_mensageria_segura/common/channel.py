"""Canal de controle servidor <-> cliente (mensagens administrativas).

Protege confirmação de registro, lista de peers, avisos de desconexão e erros
com AES-128-GCM e contador `seq_no` por direção (anti-replay).

    Z_cs   = ECDH(sk_C, pk_S)
    PRK    = HKDF-Extract(salt_srv, Z_cs)
    K_C2S  = HKDF-Expand(PRK, "C2S", 16)     K_S2C = HKDF-Expand(PRK, "S2C", 16)

    nonce  = direction (4B: 0 = c2s, 1 = s2c) || seq_no (8B, big-endian)
    AAD    = tipo do frame (1B) || seq_no (8B)
    payload do frame = seq_no (8B) || ciphertext+tag

Este canal NÃO transporta mensagens E2E: elas são cifradas só entre os clientes.
"""
from __future__ import annotations

from . import crypto
from .protocol import SEQ_LEN, TAG_LEN

DIR_C2S = 0
DIR_S2C = 1


class ChannelError(Exception):
    """Frame de controle inválido: tag incorreta, replay ou formato errado."""


class ControlChannel:
    def __init__(self, key_send: bytes, key_recv: bytes, dir_send: int, dir_recv: int):
        self._key_send = key_send
        self._key_recv = key_recv
        self._dir_send = dir_send.to_bytes(4, "big")
        self._dir_recv = dir_recv.to_bytes(4, "big")
        self.seq_send = 0     # próximo seq_no a enviar
        self.seq_recv = -1    # último seq_no aceito

    def seal(self, ftype: int, plaintext: bytes = b"") -> bytes:
        """Cifra e devolve o payload (seq_no || ciphertext+tag)."""
        seq = self.seq_send
        if seq >= 2 ** 64:
            raise ChannelError("seq_no esgotado: reabra a sessão")
        self.seq_send = seq + 1
        seq_b = seq.to_bytes(SEQ_LEN, "big")
        nonce = self._dir_send + seq_b
        ct = crypto.aead_seal(self._key_send, nonce, plaintext, bytes([ftype]) + seq_b)
        return seq_b + ct

    def open(self, ftype: int, payload: bytes) -> bytes:
        """Verifica a tag, depois o anti-replay; só então avança seq_recv."""
        if len(payload) < SEQ_LEN + TAG_LEN:
            raise ChannelError("frame de controle curto demais")
        seq_b = payload[:SEQ_LEN]
        seq = int.from_bytes(seq_b, "big")
        nonce = self._dir_recv + seq_b
        try:
            plain = crypto.aead_open(self._key_recv, nonce, payload[SEQ_LEN:],
                                     bytes([ftype]) + seq_b)
        except crypto.AuthenticationError as exc:
            raise ChannelError("tag GCM inválida no canal de controle") from exc
        if seq <= self.seq_recv:
            raise ChannelError("replay no canal de controle (seq_no já usado)")
        self.seq_recv = seq
        return plain
