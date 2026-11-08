"""Framing sobre TCP: prefixo de 4 bytes (big-endian) com o tamanho do frame.

O "tamanho" cobre o byte de tipo + payload. Todo tamanho é validado ANTES de
qualquer alocação: comprimento 0 ou acima do limite é erro de framing e a
conexão deve ser encerrada (requisito do enunciado: "framing inválido deve ser
tratado como erro e desconexão segura").
"""
from __future__ import annotations

import asyncio

from .protocol import E2E_MAX_LEN

LEN_PREFIX = 4
# Maior frame legítimo: tipo (1B) + frame E2E com 4096 B de texto claro.
MAX_FRAME_BODY = 1 + E2E_MAX_LEN   # 4165
BODY_TIMEOUT = 30.0                # tempo máximo para receber o corpo após o cabeçalho


class FramingError(Exception):
    """Tamanho inválido, corpo truncado/lento ou frame malformado."""


def encode_frame(ftype: int, payload: bytes) -> bytes:
    body = bytes([ftype]) + payload
    if len(body) > MAX_FRAME_BODY:
        raise FramingError(f"frame grande demais para enviar ({len(body)} bytes)")
    return len(body).to_bytes(LEN_PREFIX, "big") + body


async def read_frame(reader: asyncio.StreamReader,
                     max_len: int = MAX_FRAME_BODY,
                     body_timeout: float = BODY_TIMEOUT) -> tuple[int, bytes]:
    """Lê um frame e devolve (tipo, payload).

    - EOF antes/durante o frame -> asyncio.IncompleteReadError (o chamador trata
      como desconexão).
    - Tamanho 0 ou > max_len, ou corpo que não chega a tempo -> FramingError.
    """
    header = await reader.readexactly(LEN_PREFIX)
    n = int.from_bytes(header, "big")
    if n < 1 or n > max_len:
        raise FramingError(f"tamanho de frame inválido: {n} (limite {max_len})")
    try:
        body = await asyncio.wait_for(reader.readexactly(n), body_timeout)
    except asyncio.TimeoutError as exc:
        raise FramingError("timeout ao receber o corpo do frame") from exc
    return body[0], body[1:]
