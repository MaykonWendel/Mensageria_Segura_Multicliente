"""Política de logs: nada de bytes (chaves, salts, nonces) nos registros."""
import logging

from common.log_utils import NoBinaryArgsFilter


def _record(msg, args):
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, args, None)


def test_filter_blocks_bytes_args():
    f = NoBinaryArgsFilter()
    for args in [(b"\x01\x02",), (bytearray(b"k"),), ({"k": b"x"},)]:
        r = _record("valor %s" if not isinstance(args[0], dict) else "valor %(k)s", args)
        f.filter(r)
        assert "BLOQUEADO" in r.getMessage()


def test_filter_allows_text_and_numbers():
    f = NoBinaryArgsFilter()
    r = _record("cliente %s enviou %d bytes", ("abcd1234", 99))
    f.filter(r)
    assert r.getMessage() == "cliente abcd1234 enviou 99 bytes"


def test_no_secret_in_logs_during_full_session(rsa_material, caplog):
    """Roda uma sessão completa e confere que nenhum segredo/texto claro aparece nos logs."""
    import asyncio
    from tests.conftest import Env, wait_until

    secret_text = "SEGREDO-ULTRA-12345"

    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], secret_text)
            await wait_until(lambda: b.messages)
            secrets = [bytes(a.salt), bytes(a.peers[b.client_id].key_send),
                       bytes(a.peers[b.client_id].key_recv), bytes(a.peers[b.client_id].iv_base_send)]
            return secrets

    with caplog.at_level(logging.DEBUG):
        secrets = asyncio.run(go())
    logs = caplog.text
    assert secret_text not in logs
    for s in secrets:
        assert s.hex() not in logs
