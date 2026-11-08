#!/usr/bin/env python3
"""Demonstração automática dos testes mínimos obrigatórios do TP3.

    python demo.py

Sobe um servidor local (porta efêmera, certificado gerado em memória), conecta 3 clientes
e executa:
  1. troca de mensagens E2E entre 2 clientes (o 3º não recebe nada; o servidor só vê ciphertext)
  2. bitflip no tráfego        -> destinatário rejeita (falha da tag GCM)
  3. replay de frame           -> destinatário rejeita (seq_no já usado)
  4. framing inválido          -> servidor fecha a conexão e continua de pé
  5. servidor impostor (MITM)  -> cliente aborta (pinning + RSA-PSS)
  6. reconexão com o mesmo id  -> novas chaves, contadores zerados

Termina com código 0 se tudo passar.
"""
from __future__ import annotations

import asyncio
import logging
import sys

from client import HandshakeError, SecureClient
from common import certs, crypto, protocol
from server import RelayServer
from tools.framing_attack import CASES, run_case

GREEN, RED, BOLD, DIM, RESET = "\033[32m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"
results: list[tuple[str, bool]] = []


def title(text: str) -> None:
    print(f"\n{BOLD}== {text} =={RESET}")


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    mark = f"{GREEN}✔ PASSOU{RESET}" if ok else f"{RED}✘ FALHOU{RESET}"
    print(f"  {mark}  {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))


async def wait_until(cond, timeout=3.0):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return True
        await asyncio.sleep(0.01)
    return cond()


async def main() -> int:
    logging.getLogger().setLevel(logging.CRITICAL)      # saída limpa; os logs reais são do server.py
    print("Gerando chave RSA-2048 e certificado autoassinado do servidor...")
    key, cert = certs.generate_self_signed("tp3-demo")
    seen: list[bytes] = []
    server = RelayServer(key, certs.cert_to_der(cert), port=0, relay_hook=seen.append)
    port = await server.start()
    clients: list[SecureClient] = []

    async def new_client(**kw) -> SecureClient:
        c = SecureClient("127.0.0.1", port, cert, **kw)
        await c.connect()
        clients.append(c)
        return c

    try:
        # ---------------------------------------------------------------- handshake
        title("Handshake autenticado e distribuição de chaves")
        a, b, c = await new_client(), await new_client(), await new_client()
        await wait_until(lambda: all(len(x.peers) == 2 for x in (a, b, c)))
        for name, x in (("A", a), ("B", b), ("C", c)):
            print(f"  {name}: id {x.client_id.hex()[:8]}  fingerprint {crypto.fingerprint(x.public_key)}")
        check("3 clientes registrados; cada um recebeu as chaves públicas dos outros",
              all(len(x.peers) == 2 for x in (a, b, c)) and len(server.sessions) == 3)
        pa, pb = a.peers[b.client_id], b.peers[a.client_id]
        check("A e B derivaram as mesmas chaves (A2B/B2A) sem trocá-las pela rede",
              pa.key_send == pb.key_recv and pa.key_recv == pb.key_send and pa.key_send != pa.key_recv)

        # ---------------------------------------------------------------- teste 1
        title("Teste 1 - mensagens E2E")
        text = "Segredo: a prova é na sexta!"
        await a.send_message(pa, text)
        await b.send_message(pb, "Recebi, A. Obrigado!")
        await wait_until(lambda: a.messages and b.messages)
        check("B decifrou a mensagem de A", b.messages == [(a.client_id, text)], f'B leu: "{b.messages[0][1]}"' if b.messages else "")
        check("A decifrou a resposta de B", len(a.messages) == 1)
        await asyncio.sleep(0.1)
        check("C (terceiro cliente) não recebeu nada", not c.messages and not c.rejections)
        check("o servidor repassou apenas bytes cifrados (texto claro não aparece no tráfego)",
              bool(seen) and all(text.encode() not in f for f in seen),
              f"ciphertext visto pelo servidor: {seen[0][protocol.OFF_CT:protocol.OFF_CT + 12].hex()}...")

        # ---------------------------------------------------------------- teste 2
        title("Teste 2 - adulteração (bitflip) no tráfego")
        server.demo_tamper = True
        b.messages.clear(), b.rejections.clear()
        await a.send_message(pa, "transfira R$ 100 para Maria")
        await wait_until(lambda: b.rejections)
        check("B rejeitou o frame adulterado (tag GCM inválida)", bool(b.rejections) and "tag GCM" in b.rejections[0],
              b.rejections[0] if b.rejections else "")
        check("a mensagem adulterada NÃO foi entregue e o estado de B não avançou",
              not b.messages and pb.seq_recv == 0)
        server.demo_tamper = False
        await a.send_message(pa, "mensagem legítima seguinte")
        await wait_until(lambda: b.messages)
        check("a sessão continua funcionando depois do ataque", len(b.messages) == 1)

        # ---------------------------------------------------------------- teste 3
        title("Teste 3 - replay de frame")
        server.demo_replay = True
        b.messages.clear(), b.rejections.clear()
        await a.send_message(pa, "pague 10 reais ao fornecedor")
        await wait_until(lambda: b.messages and b.rejections)
        server.demo_replay = False
        check("B entregou a mensagem uma única vez", len(b.messages) == 1)
        check("B rejeitou o frame repetido (seq_no já usado)", bool(b.rejections) and "replay" in b.rejections[0],
              b.rejections[0] if b.rejections else "")
        b.rejections.clear()
        await a.replay_last()
        await wait_until(lambda: b.rejections)
        check("reenvio manual do último frame também é rejeitado", bool(b.rejections))

        # ---------------------------------------------------------------- teste 4
        title("Teste 4 - framing inválido")
        for name in (n for n in CASES if n != "slowloris"):
            closed = await run_case("127.0.0.1", port, name)
            check(f"framing inválido '{name}': servidor fechou a conexão", closed)
        await a.send_message(pa, "o servidor sobreviveu")
        await wait_until(lambda: any(t == "o servidor sobreviveu" for _, t in b.messages))
        check("servidor continua atendendo os demais clientes", any(t == "o servidor sobreviveu" for _, t in b.messages))

        # ---------------------------------------------------------------- teste 5
        title("Teste 5 - servidor impostor (MITM no registro de chaves)")
        evil_key, evil_cert = certs.generate_self_signed("impostor")
        evil = RelayServer(evil_key, certs.cert_to_der(evil_cert), port=0)
        eport = await evil.start()
        try:
            await SecureClient("127.0.0.1", eport, cert).connect()
            check("cliente recusa servidor com outro certificado", False)
        except HandshakeError as exc:
            check("cliente recusa servidor com outro certificado", True, str(exc))
        finally:
            await evil.stop()
        evil2 = RelayServer(evil_key, certs.cert_to_der(cert), port=0)   # cert legítimo, assina com chave errada
        eport = await evil2.start()
        try:
            await SecureClient("127.0.0.1", eport, cert).connect()
            check("cliente recusa assinatura RSA-PSS feita com a chave errada", False)
        except HandshakeError as exc:
            check("cliente recusa assinatura RSA-PSS feita com a chave errada", True, str(exc))
        finally:
            await evil2.stop()

        # ---------------------------------------------------------------- teste 6
        title("Teste 6 - reconexão com o mesmo client_id")
        bid, old_key, old_salt = b.client_id, a.peers[b.client_id].key_send, b.salt
        await b.close()
        await wait_until(lambda: bid not in a.peers and bid not in server.sessions)
        check("sessão de B removida do servidor e dos peers de A", bid not in a.peers and bid not in server.sessions)
        b2 = await new_client(client_id=bid)
        await wait_until(lambda: bid in a.peers and a.client_id in b2.peers)
        p = a.peers[bid]
        check("novo handshake: novo salt, novas chaves e contadores zerados",
              p.key_send != old_key and b2.salt != old_salt and (p.seq_send, p.seq_recv) == (0, -1))
        await a.send_message(p, "bem-vindo de volta")
        await wait_until(lambda: b2.messages)
        check("mensagens funcionam na nova sessão", len(b2.messages) == 1)
    finally:
        for x in clients:
            await x.close()
        await server.stop()

    passed = sum(ok for _, ok in results)
    print(f"\n{BOLD}Resumo: {passed}/{len(results)} verificações passaram.{RESET}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
