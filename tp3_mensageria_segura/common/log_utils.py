"""Política de logs do projeto.

PERMITIDO: conexão/desconexão, client_id, tamanhos, motivo de rejeição,
fingerprints de chaves públicas.

PROIBIDO: chaves privadas, segredo ECDH (Z), chaves derivadas, salt, nonces e
conteúdo de mensagens.

Como defesa em profundidade, `NoBinaryArgsFilter` bloqueia qualquer registro de
log que receba `bytes` como argumento: se alguém tentar logar uma chave ou um
salt por engano, o conteúdo é descartado em vez de ir para o terminal/arquivo.
"""
from __future__ import annotations

import logging
import uuid


class NoBinaryArgsFilter(logging.Filter):
    BLOCKED = "[LOG BLOQUEADO: dado binário não pode ser registrado]"

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, dict):
            values = list(args.values())
        elif isinstance(args, tuple):
            values = list(args)
        elif args:
            values = [args]
        else:
            values = []
        if any(isinstance(v, (bytes, bytearray, memoryview)) for v in values):
            record.msg = self.BLOCKED
            record.args = ()
        elif isinstance(record.msg, (bytes, bytearray, memoryview)):
            record.msg = self.BLOCKED
        return True


def setup_logging(verbose: bool = False) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                                           datefmt="%H:%M:%S"))
    handler.addFilter(NoBinaryArgsFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


def cid(client_id: bytes) -> str:
    """client_id completo em texto (UUID)."""
    return str(uuid.UUID(bytes=client_id))


def sid(client_id: bytes) -> str:
    """client_id curto (8 hex) para mensagens de log."""
    return client_id[:4].hex()
