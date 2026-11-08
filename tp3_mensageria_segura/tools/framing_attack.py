#!/usr/bin/env python3
"""Envia frames inválidos ao servidor e verifica que ele fecha a conexão com segurança.

    python tools/framing_attack.py --host 127.0.0.1 --port 8443

Casos:
  oversize   : declara tamanho 0xFFFFFFFF (o servidor não pode alocar/ler isso)
  zero       : declara tamanho 0
  garbage    : bytes aleatórios no lugar de um frame HELLO
  wrongtype  : frame bem formado, mas de tipo inesperado no início da conexão
  badhello   : HELLO com payload de tamanho errado
  badid      : HELLO bem formado, mas com client_id que não é UUID v4
  slowloris  : declara 40 bytes (tamanho válido), envia 10 e fica parado (testa o timeout; use --slow)
"""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import protocol  # noqa: E402

CASES = {
    "oversize": lambda: b"\xff\xff\xff\xff" + b"\x01" * 16,
    "zero": lambda: b"\x00\x00\x00\x00",
    "garbage": lambda: os.urandom(64),
    "wrongtype": lambda: (2).to_bytes(4, "big") + bytes([protocol.T_E2E, 0]),
    "badhello": lambda: (10).to_bytes(4, "big") + bytes([protocol.T_HELLO]) + b"\x00" * 9,
    "badid": lambda: ((1 + 16 + 32).to_bytes(4, "big") + bytes([protocol.T_HELLO])
                      + b"\x00" * 16 + os.urandom(32)),
    "slowloris": lambda: (40).to_bytes(4, "big") + b"\x01" * 10,
}


async def run_case(host: str, port: int, name: str, timeout: float = 5.0) -> bool:
    """True se o servidor encerrou a conexão (comportamento correto)."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(CASES[name]())
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(65536), timeout)
        closed = data == b""    # EOF sem resposta = conexão fechada pelo servidor
    except (asyncio.TimeoutError, ConnectionError):
        closed = False   # o servidor não fechou a conexão no prazo
    except OSError:
        closed = True
    writer.close()
    return closed


async def main_async(host: str, port: int, slow: bool) -> int:
    failures = 0
    for name in CASES:
        if name == "slowloris" and not slow:
            continue
        ok = await run_case(host, port, name, timeout=15.0 if name == "slowloris" else 5.0)
        print(f"  {'OK ' if ok else 'FALHA'}  {name:10s} -> servidor {'fechou a conexão' if ok else 'NÃO fechou'}")
        failures += 0 if ok else 1
    return failures


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--slow", action="store_true", help="inclui o caso slowloris (~10 s)")
    a = ap.parse_args()
    sys.exit(1 if asyncio.run(main_async(a.host, a.port, a.slow)) else 0)
