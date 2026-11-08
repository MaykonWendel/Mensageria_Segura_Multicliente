"""Testes de integração: servidor e clientes reais sobre TCP local."""
import asyncio
import os
import uuid

import pytest

from client import HandshakeError, SecureClient
from common import certs, crypto, framing, protocol
from server import RelayServer
from tests.conftest import Env, wait_until
from tools.framing_attack import run_case


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


# ===================================================================== Teste 1: E2E
def test_two_clients_exchange_messages_e2e(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], "olá, B! 🔐")
            await b.send_message(b.peers[a.client_id], "oi, A!")
            assert await wait_until(lambda: a.messages and b.messages)
            assert b.messages == [(a.client_id, "olá, B! 🔐")]
            assert a.messages == [(b.client_id, "oi, A!")]
            assert not a.rejections and not b.rejections
    run(go())


def test_three_clients_only_recipient_receives(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            c = await env.client()
            assert await wait_until(lambda: len(a.peers) == 2 and len(b.peers) == 2 and len(c.peers) == 2)
            await a.send_message(a.peers[b.client_id], "só para o B")
            assert await wait_until(lambda: b.messages)
            await asyncio.sleep(0.1)
            assert c.messages == [] and c.rejections == []     # C nem recebe o frame
            # e a chave A<->C é diferente da A<->B
            assert a.peers[b.client_id].key_send != a.peers[c.client_id].key_send
    run(go())


def test_new_client_receives_existing_and_vice_versa(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a = await env.client()
            b = await env.client()
            c = await env.client()
            assert await wait_until(lambda: len(a.peers) == 2 and len(b.peers) == 2 and len(c.peers) == 2)
            for x, others in ((a, (b, c)), (b, (a, c)), (c, (a, b))):
                assert set(x.peers) == {o.client_id for o in others}
    run(go())


def test_key_derivation_is_symmetric_and_directional(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            pa, pb = a.peers[b.client_id], b.peers[a.client_id]
            assert pa.key_send == pb.key_recv and pa.key_recv == pb.key_send
            assert pa.key_send != pa.key_recv
            assert len(pa.key_send) == 16
            assert (pa.seq_send, pa.seq_recv, pb.seq_send, pb.seq_recv) == (0, -1, 0, -1)
    run(go())


def test_many_messages_in_both_directions_keep_counters(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            for i in range(20):
                await a.send_message(a.peers[b.client_id], f"a{i}")
                await b.send_message(b.peers[a.client_id], f"b{i}")
            assert await wait_until(lambda: len(a.messages) == 20 and len(b.messages) == 20)
            assert [t for _, t in b.messages] == [f"a{i}" for i in range(20)]
            assert b.peers[a.client_id].seq_recv == 19 and a.peers[b.client_id].seq_send == 20
    run(go())


def test_max_plaintext_4096_ok_and_4097_rejected(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            big = "x" * 4096
            await a.send_message(a.peers[b.client_id], big)
            assert await wait_until(lambda: b.messages)
            assert b.messages[0][1] == big
            with pytest.raises(ValueError):
                await a.send_message(a.peers[b.client_id], "x" * 4097)
            # a falha não consome o seq_no nem quebra a sessão
            await a.send_message(a.peers[b.client_id], "depois")
            assert await wait_until(lambda: len(b.messages) == 2)
    run(go())


# ===================================================================== servidor cego
def test_server_cannot_read_messages(rsa_material):
    captured = []

    async def go():
        async with Env(rsa_material, relay_hook=captured.append) as env:
            a, b = await env.pair()
            text = "texto-claro-que-o-servidor-nao-pode-ver"
            await a.send_message(a.peers[b.client_id], text)
            assert await wait_until(lambda: b.messages)
            assert captured and all(text.encode() not in frame for frame in captured)
            # o servidor não guarda nenhuma chave E2E em lugar nenhum
            keys = {a.peers[b.client_id].key_send, a.peers[b.client_id].key_recv}
            held = []
            for s in env.server.sessions.values():
                for v in vars(s).values():
                    if isinstance(v, (bytes, bytearray)):
                        held.append(bytes(v))
                for v in vars(s.channel).values():
                    if isinstance(v, (bytes, bytearray)):
                        held.append(bytes(v))
            assert not (keys & set(held))
            assert not any(hasattr(s, "key_send") for s in env.server.sessions.values())
    run(go())


# ===================================================================== Teste 2: bitflip
def test_bitflip_by_malicious_relay_is_rejected(rsa_material):
    async def go():
        async with Env(rsa_material, demo_tamper=True) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], "mensagem original")
            assert await wait_until(lambda: b.rejections)
            assert "tag GCM" in b.rejections[0]
            assert b.messages == []
            assert b.peers[a.client_id].seq_recv == -1      # estado NÃO avançou
            # sem o atacante, a próxima mensagem legítima passa normalmente
            env.server.demo_tamper = False
            await a.send_message(a.peers[b.client_id], "segunda")
            assert await wait_until(lambda: b.messages)
            assert b.messages[0][1] == "segunda"
    run(go())


def test_bitflip_in_header_fields_is_rejected(rsa_material):
    """Alterar seq_no ou o IV_base também falha (nonce/AAD/tag)."""
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            pa = a.peers[b.client_id]
            for offset in (0, protocol.OFF_SEQ + 7, protocol.OFF_CT + 3):
                body = bytearray(a._build_e2e(pa, "x"))
                body[offset] ^= 0x01
                await a._send_frame(protocol.T_E2E, bytes(body))
            assert await wait_until(lambda: len(b.rejections) == 3)
            assert b.messages == []
    run(go())


def test_client_side_tamper_helper(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            await a.send_tampered(a.peers[b.client_id], "x")
            assert await wait_until(lambda: b.rejections)
            assert "tag GCM" in b.rejections[0]
    run(go())


# ===================================================================== Teste 3: replay
def test_replay_by_malicious_relay_is_rejected(rsa_material):
    async def go():
        async with Env(rsa_material, demo_replay=True) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], "pague 10 reais")
            assert await wait_until(lambda: b.messages and b.rejections)
            assert len(b.messages) == 1                      # entregue UMA vez
            assert "replay" in b.rejections[0]
    run(go())


def test_replay_of_last_frame_from_client(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], "m1")
            assert await wait_until(lambda: b.messages)
            await a.replay_last()
            assert await wait_until(lambda: b.rejections)
            assert "replay" in b.rejections[0] and len(b.messages) == 1
    run(go())


def test_old_or_reordered_seq_is_rejected(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            pa = a.peers[b.client_id]
            f0, f1 = a._build_e2e(pa, "primeira"), a._build_e2e(pa, "segunda")
            await a._send_frame(protocol.T_E2E, f1)        # seq 1 chega antes
            await a._send_frame(protocol.T_E2E, f0)        # seq 0 chega depois -> velho
            assert await wait_until(lambda: b.messages and b.rejections)
            assert [t for _, t in b.messages] == ["segunda"]
            assert "replay" in b.rejections[0]
    run(go())


def test_iv_base_must_stay_constant_in_session(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            pa = a.peers[b.client_id]
            await a.send_message(pa, "um")
            assert await wait_until(lambda: b.messages)
            pa.iv_base_send = os.urandom(4)                # remetente "troca" o IV_base
            await a.send_message(pa, "dois")
            assert await wait_until(lambda: b.rejections)
            assert "IV_base" in b.rejections[0]
    run(go())


def test_replay_of_old_session_frame_fails_after_reconnect(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            await a.send_message(a.peers[b.client_id], "sessão antiga")
            assert await wait_until(lambda: b.messages)
            bid = b.client_id
            await b.close()
            assert await wait_until(lambda: bid not in a.peers)
            b2 = await env.client(client_id=bid)
            assert await wait_until(lambda: bid in a.peers and a.client_id in b2.peers)
            await a.replay_last()                           # frame da sessão anterior
            assert await wait_until(lambda: b2.rejections)
            assert "tag GCM" in b2.rejections[0] and b2.messages == []
    run(go())


# ===================================================================== Teste 4: framing inválido
@pytest.mark.parametrize("case", ["oversize", "zero", "garbage", "wrongtype", "badhello", "badid"])
def test_invalid_framing_closes_connection_and_server_survives(rsa_material, case):
    async def go():
        async with Env(rsa_material) as env:
            assert await run_case("127.0.0.1", env.port, case, timeout=5)
            a, b = await env.pair()                         # servidor continua atendendo
            await a.send_message(a.peers[b.client_id], "ainda funciona")
            assert await wait_until(lambda: b.messages)
    run(go())


def test_invalid_e2e_frame_size_after_handshake_disconnects(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            a.writer.write(framing.encode_frame(protocol.T_E2E, b"\x00" * 10))   # menor que o mínimo
            assert await wait_until(lambda: a.disconnected.is_set())
            assert a.client_id not in env.server.sessions
            assert await wait_until(lambda: a.client_id not in b.peers)
    run(go())


def test_oversize_length_after_handshake_disconnects(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, _ = await env.pair()
            a.writer.write(b"\xff\xff\xff\xff")
            assert await wait_until(lambda: a.disconnected.is_set())
            assert a.client_id not in env.server.sessions
    run(go())


# ===================================================================== autenticação do servidor
def test_pinning_rejects_server_with_other_certificate(rsa_material, other_cert):
    """MITM com certificado próprio: o cliente pinou outro certificado."""
    okey, ocert = other_cert

    async def go():
        evil = RelayServer(okey, certs.cert_to_der(ocert), port=0)
        port = await evil.start()
        try:
            c = SecureClient("127.0.0.1", port, rsa_material[1])    # pinado = certificado legítimo
            with pytest.raises(HandshakeError, match="pinado"):
                await c.connect()
        finally:
            await evil.stop()
    run(go())


def test_signature_with_wrong_key_is_rejected(rsa_material, other_cert):
    """Atacante apresenta o certificado legítimo (público) mas assina com a sua própria chave."""
    okey, _ = other_cert

    async def go():
        evil = RelayServer(okey, certs.cert_to_der(rsa_material[1]), port=0)
        port = await evil.start()
        try:
            c = SecureClient("127.0.0.1", port, rsa_material[1])
            with pytest.raises(HandshakeError, match="assinatura"):
                await c.connect()
        finally:
            await evil.stop()
    run(go())


async def _tamper_proxy(target_port, flip_index):
    """Proxy TCP que inverte 1 bit na resposta do servidor (simula MITM ativo)."""
    async def handle(cr, cw):
        sr, sw = await asyncio.open_connection("127.0.0.1", target_port)

        async def c2s():
            try:
                while data := await cr.read(65536):
                    sw.write(data)
                    await sw.drain()
            except Exception:
                pass
            sw.close()

        async def s2c():
            first = True
            try:
                while data := await sr.read(65536):
                    if first:
                        b = bytearray(data)
                        b[flip_index] ^= 0x01
                        data, first = bytes(b), False
                    cw.write(data)
                    await cw.drain()
            except Exception:
                pass
            cw.close()
        await asyncio.gather(c2s(), s2c())
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


@pytest.mark.parametrize("where,index", [("pk_S", 10), ("salt", 5 + 32 + 3), ("assinatura", 5 + 32 + 16 + 2 + 10)])
def test_mitm_modifying_handshake_is_detected(rsa_material, where, index):
    async def go():
        async with Env(rsa_material) as env:
            proxy, pport = await _tamper_proxy(env.port, index)
            try:
                c = SecureClient("127.0.0.1", pport, rsa_material[1])
                with pytest.raises(HandshakeError):
                    await c.connect()
            finally:
                proxy.close()
    run(go())


def test_server_ephemeral_key_and_salt_change_every_connection(rsa_material):
    """Sigilo perfeito: pk_S é efêmera (RSA só assina) e o salt é novo a cada handshake."""
    async def raw_handshake(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        _, pk_c = crypto.generate_x25519()
        w.write(framing.encode_frame(protocol.T_HELLO, protocol.pack_hello(uuid.uuid4().bytes, pk_c)))
        await w.drain()
        ftype, payload = await framing.read_frame(r)
        w.close()
        assert ftype == protocol.T_HELLO_REPLY
        rep = protocol.parse_hello_reply(payload)
        return rep.pk_s, rep.salt

    async def go():
        async with Env(rsa_material) as env:
            (pk1, s1), (pk2, s2) = await raw_handshake(env.port), await raw_handshake(env.port)
            assert pk1 != pk2 and s1 != s2
    run(go())


# ===================================================================== sessões
def test_disconnect_cleans_state_and_notifies_peers(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            bid = b.client_id
            await b.close()
            assert await wait_until(lambda: bid not in a.peers)
            assert bid not in env.server.sessions
    run(go())


def test_reconnect_same_id_derives_fresh_keys_and_counters(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            bid = b.client_id
            old_key, old_pk, old_salt = a.peers[bid].key_send, a.peers[bid].public_key, b.salt
            await a.send_message(a.peers[bid], "antes")
            assert await wait_until(lambda: b.messages)
            await b.close()
            assert await wait_until(lambda: bid not in a.peers)
            b2 = await env.client(client_id=bid)
            assert await wait_until(lambda: bid in a.peers and a.client_id in b2.peers)
            p = a.peers[bid]
            assert p.key_send != old_key and p.public_key != old_pk and b2.salt != old_salt
            assert (p.seq_send, p.seq_recv) == (0, -1)
            await a.send_message(p, "depois")
            await b2.send_message(b2.peers[a.client_id], "volta")
            assert await wait_until(lambda: b2.messages and a.messages)
            assert b2.messages[0][1] == "depois"
    run(go())


def test_duplicate_client_id_is_refused_while_connected(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            with pytest.raises(HandshakeError, match="em uso"):
                await env.client(client_id=a.client_id)
            # a sessão original não foi afetada
            await a.send_message(a.peers[b.client_id], "ainda aqui")
            assert await wait_until(lambda: b.messages)
    run(go())


def test_sender_spoofing_is_blocked_by_server(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            c = await env.client()
            assert await wait_until(lambda: len(a.peers) == 2)
            body = bytearray(a._build_e2e(a.peers[b.client_id], "forjada"))
            body[protocol.OFF_SENDER:protocol.OFF_RECIPIENT] = c.client_id   # finge ser o C
            await a._send_frame(protocol.T_E2E, bytes(body))
            assert await wait_until(lambda: a.server_errors)
            assert a.server_errors[0][0] == protocol.ERR_BAD_SENDER
            await asyncio.sleep(0.1)
            assert b.messages == [] and b.rejections == []
    run(go())


def test_message_to_offline_recipient_reports_error(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            peer = a.peers[b.client_id]
            bid = b.client_id
            await b.close()
            assert await wait_until(lambda: bid not in a.peers)
            await a.send_message(peer, "ninguém ouve")
            assert await wait_until(lambda: a.server_errors)
            assert a.server_errors[0] == (protocol.ERR_RECIPIENT_OFFLINE, bid)
    run(go())


def test_control_channel_replay_disconnects_client(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, _ = await env.pair()
            payload = a.channel.seal(protocol.T_LIST_REQ)
            frame = framing.encode_frame(protocol.T_LIST_REQ, payload)
            a.writer.write(frame)          # legítimo
            a.writer.write(frame)          # replay do mesmo frame de controle
            assert await wait_until(lambda: a.client_id not in env.server.sessions)
    run(go())


def test_list_request_returns_peers_again(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            a.peers.clear()
            await a.request_peer_list()
            assert await wait_until(lambda: b.client_id in a.peers)
            await a.send_message(a.peers[b.client_id], "após /refresh")
            assert await wait_until(lambda: b.messages)
    run(go())


def test_server_seq_counters_follow_spec(rsa_material):
    async def go():
        async with Env(rsa_material) as env:
            a, b = await env.pair()
            s = env.server.sessions[a.client_id]
            assert s.seq_recv == -1                 # nada recebido ainda no canal de controle c2s
            assert s.seq_send >= 2                  # ACK + PEER_INFO já enviados
            await a.request_peer_list()
            assert await wait_until(lambda: s.seq_recv == 0)
    run(go())


def test_max_clients_limit_is_enforced_and_recovers(rsa_material):
    async def go():
        async with Env(rsa_material, max_clients=2) as env:
            a, b = await env.pair()
            with pytest.raises(HandshakeError):
                await env.client()
            await b.close()
            assert await wait_until(lambda: env.server._connections == 1)
            c = await env.client()                  # volta a aceitar
            assert await wait_until(lambda: a.client_id in c.peers)
    run(go())
