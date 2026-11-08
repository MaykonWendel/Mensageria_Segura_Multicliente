#!/usr/bin/env python3
"""Cliente do TP3 - Mensageria Segura Multi-Cliente (E2E).

`SecureClient` implementa o protocolo (handshake autenticado, derivação de chaves
E2E, AES-128-GCM com nonce/seq_no, anti-replay). `main()` é uma CLI interativa.

Uso:
    python client.py --host 127.0.0.1 --port 8443 --cert certs/server.crt
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import logging
import os
import sys
import threading
import uuid
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from common import certs, crypto, framing, protocol
from common.channel import DIR_C2S, DIR_S2C, ChannelError, ControlChannel
from common.framing import FramingError
from common.log_utils import cid, setup_logging, sid
from common.protocol import ProtocolError

log = logging.getLogger("client")

CONNECT_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 10.0
WRITE_TIMEOUT = 10.0


class HandshakeError(Exception):
    """Falha ao autenticar o servidor ou ao se registrar."""


class Peer:
    """Entrada da tabela `peers` (um outro cliente).

    Z_AB não é guardado: é descartado logo após a derivação das chaves.
    """
    __slots__ = ("client_id", "public_key", "salt", "key_send", "key_recv", "seq_send", "seq_recv",
                 "iv_base_send", "iv_base_recv")

    def __init__(self, client_id: bytes, public_key: bytes, salt: bytes,
                 key_send: bytes, key_recv: bytes):
        self.client_id = client_id
        self.public_key = public_key                       # pk_C do peer (32B)
        self.salt = salt                                   # salt_srv do peer (identifica a sessão dele)
        self.key_send = key_send                           # Key_A2B (se eu sou A) ou Key_B2A
        self.key_recv = key_recv
        self.seq_send = 0                                  # próximo seq_no a enviar
        self.seq_recv = -1                                 # último seq_no aceito
        self.iv_base_send = os.urandom(protocol.IV_BASE_LEN)   # aleatório por direção/sessão
        self.iv_base_recv: Optional[bytes] = None          # aprendido (e autenticado) na 1ª msg válida

    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(self.public_key)


def derive_e2e_keys(sk, my_id: bytes, my_salt: bytes, peer_id: bytes, peer_pk: bytes,
                    peer_salt: bytes) -> tuple[bytes, bytes]:
    """Deriva (key_send, key_recv) para o par (eu, peer).

    Regra determinística: o MENOR client_id (comparação de bytes) é "A".
      Z        = ECDH(sk_eu, pk_peer)
      salt_par = SHA256(salt_do_menor_id || salt_do_maior_id)[:16]
      PRK      = HKDF-Extract(salt_par, Z)
      Key_A2B  = HKDF-Expand(PRK, "A2B", 16)     Key_B2A = HKDF-Expand(PRK, "B2A", 16)
    Quem é A envia com A2B e recebe com B2A; quem é B faz o inverso.
    """
    z = crypto.x25519_exchange(sk, peer_pk)
    i_am_a = my_id < peer_id
    salt_lo, salt_hi = (my_salt, peer_salt) if i_am_a else (peer_salt, my_salt)
    salt_par = hashlib.sha256(salt_lo + salt_hi).digest()[:protocol.SALT_LEN]
    prk = crypto.hkdf_extract(salt_par, z)
    del z   # Z_AB não é mantido
    k_a2b = crypto.hkdf_expand(prk, b"A2B", protocol.KEY_LEN)
    k_b2a = crypto.hkdf_expand(prk, b"B2A", protocol.KEY_LEN)
    return (k_a2b, k_b2a) if i_am_a else (k_b2a, k_a2b)


class SecureClient:
    def __init__(self, host: str, port: int, pinned_cert, client_id: Optional[bytes] = None,
                 on_event: Optional[Callable[..., None]] = None):
        self.host, self.port = host, port
        self._pinned_cert = pinned_cert
        self._pinned_der = certs.cert_to_der(pinned_cert)
        self.client_id = client_id or uuid.uuid4().bytes
        protocol.check_uuid4(self.client_id)
        self._on_event = on_event

        self._sk, self.public_key = crypto.generate_x25519()   # par efêmero (sk nunca sai daqui)
        self.salt: bytes = b""                                 # salt_srv desta sessão
        self.channel: Optional[ControlChannel] = None
        self.peers: dict[bytes, Peer] = {}

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self.disconnected = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._wlock = asyncio.Lock()
        self._last_e2e: Optional[bytes] = None    # só para a demo de replay
        self._closing = False                     # True quando QUEM encerra somos nós

        # registros observáveis (testes/demo)
        self.messages: list[tuple[bytes, str]] = []       # (sender_id, texto)
        self.rejections: list[str] = []                   # motivos de rejeição
        self.server_errors: list[tuple[int, bytes]] = []

    # ------------------------------------------------------------------ eventos
    def _emit(self, kind: str, **info) -> None:
        if self._on_event is not None:
            try:
                self._on_event(kind, **info)
            except Exception:
                log.exception("erro no callback de evento")

    def _reject(self, reason: str, sender: Optional[bytes] = None) -> None:
        self.rejections.append(reason)
        log.warning("mensagem rejeitada%s: %s", f" de {sid(sender)}" if sender else "", reason)
        self._emit("reject", reason=reason, sender=sender)

    # ------------------------------------------------------------------ handshake
    async def connect(self) -> None:
        if not certs.is_valid_now(self._pinned_cert):
            raise HandshakeError("o certificado pinado está fora do período de validade")
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as exc:
            raise HandshakeError(f"não foi possível conectar a {self.host}:{self.port}: {exc}") from exc
        try:
            await self._handshake()
        except BaseException:
            self._close_transport()
            raise
        self.connected = True
        self._task = asyncio.create_task(self._recv_loop())

    async def _handshake(self) -> None:
        assert self.reader is not None and self.writer is not None
        try:
            self.writer.write(framing.encode_frame(
                protocol.T_HELLO, protocol.pack_hello(self.client_id, self.public_key)))
            await self.writer.drain()

            ftype, payload = await asyncio.wait_for(framing.read_frame(self.reader), HANDSHAKE_TIMEOUT)
            if ftype != protocol.T_HELLO_REPLY:
                raise HandshakeError("resposta inesperada do servidor")
            reply = protocol.parse_hello_reply(payload)

            # 1) certificado apresentado == certificado pinado
            if not hmac.compare_digest(reply.cert_der, self._pinned_der):
                raise HandshakeError("o certificado do servidor difere do certificado pinado")
            # 2) assinatura RSA-PSS sobre H, verificada com a chave do certificado PINADO
            pub = self._pinned_cert.public_key()
            if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < certs.MIN_RSA_BITS:
                raise HandshakeError("certificado pinado não contém chave RSA >= 2048 bits")
            h = crypto.handshake_hash(reply.pk_s, self.public_key, self.client_id, reply.salt)
            if not crypto.rsa_pss_verify(pub, reply.signature, h):
                raise HandshakeError("assinatura RSA-PSS do servidor inválida (possível MITM)")

            # 3) só agora confiamos em pk_S: canal de controle
            try:
                z = crypto.x25519_exchange(self._sk, reply.pk_s)
            except crypto.CryptoError as exc:
                raise HandshakeError(f"pk_S inválida: {exc}") from exc
            prk = crypto.hkdf_extract(reply.salt, z)
            k_c2s = crypto.hkdf_expand(prk, b"C2S", protocol.KEY_LEN)
            k_s2c = crypto.hkdf_expand(prk, b"S2C", protocol.KEY_LEN)
            del z, prk
            self.salt = reply.salt
            self.channel = ControlChannel(key_send=k_c2s, key_recv=k_s2c,
                                          dir_send=DIR_C2S, dir_recv=DIR_S2C)

            # 4) primeiro frame de controle: REGISTER_ACK (ou ERROR)
            ftype, payload = await asyncio.wait_for(framing.read_frame(self.reader), HANDSHAKE_TIMEOUT)
            if ftype not in (protocol.T_REGISTER_ACK, protocol.T_ERROR):
                raise HandshakeError("o servidor não confirmou o registro")
            plain = self.channel.open(ftype, payload)
            if ftype == protocol.T_ERROR:
                code, detail = protocol.parse_error(plain)
                raise HandshakeError("registro recusado: " + protocol.ERROR_TEXT.get(code, f"erro {code}"))
        except (FramingError, ProtocolError, ChannelError) as exc:
            raise HandshakeError(f"handshake inválido: {exc}") from exc
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError) as exc:
            raise HandshakeError("o servidor encerrou a conexão ou não respondeu a tempo") from exc
        log.info("conectado e registrado como %s", sid(self.client_id))

    # ------------------------------------------------------------------ recepção
    async def _recv_loop(self) -> None:
        assert self.reader is not None
        reason = "conexão encerrada"
        try:
            while True:
                ftype, payload = await framing.read_frame(self.reader)
                if ftype == protocol.T_E2E:
                    self._on_e2e(payload)
                elif ftype in protocol.CONTROL_S2C:
                    self._on_control(ftype, payload)
                else:
                    raise ProtocolError(f"tipo de frame inesperado: 0x{ftype:02x}")
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            reason = "servidor encerrou a conexão"
        except (FramingError, ProtocolError, ChannelError) as exc:
            reason = f"violação de protocolo: {exc}"
            log.error("encerrando: %s", reason)
        finally:
            self.connected = False
            self._close_transport()
            self.disconnected.set()
            self._emit("disconnected", reason=reason, local=self._closing)

    def _on_control(self, ftype: int, payload: bytes) -> None:
        assert self.channel is not None
        plain = self.channel.open(ftype, payload)      # ChannelError -> encerra a conexão
        if ftype == protocol.T_PEER_INFO:
            info = protocol.parse_peer_info(plain)
            self._add_peer(info)
        elif ftype == protocol.T_PEER_LEAVE:
            pid = protocol.parse_peer_leave(plain)
            if self.peers.pop(pid, None) is not None:
                log.info("peer %s saiu", sid(pid))
                self._emit("peer_leave", client_id=pid)
        elif ftype == protocol.T_ERROR:
            code, detail = protocol.parse_error(plain)
            self.server_errors.append((code, detail))
            log.warning("erro do servidor: %s", protocol.ERROR_TEXT.get(code, f"código {code}"))
            self._emit("server_error", code=code, detail=detail)
        # T_REGISTER_ACK repetido é ignorado

    def _add_peer(self, info: protocol.PeerInfo) -> None:
        if info.client_id == self.client_id:
            return
        # PEER_INFO repetido da MESMA sessão (ex.: /refresh): não recria o peer, senão
        # seq_send/seq_recv/IV_base voltam ao início e o anti-replay é desarmado.
        existing = self.peers.get(info.client_id)
        if existing is not None and existing.public_key == info.public_key and existing.salt == info.salt:
            return
        try:
            protocol.check_uuid4(info.client_id)
            key_send, key_recv = derive_e2e_keys(self._sk, self.client_id, self.salt,
                                                 info.client_id, info.public_key, info.salt)
        except (ProtocolError, crypto.CryptoError) as exc:
            log.warning("PEER_INFO ignorado (%s): %s", sid(info.client_id), exc)
            return
        # se já existia (reconexão), as chaves e contadores são substituídos por completo
        self.peers[info.client_id] = Peer(info.client_id, info.public_key, info.salt, key_send, key_recv)
        log.info("peer %s registrado fp=%s", sid(info.client_id), crypto.fingerprint(info.public_key))
        self._emit("peer_join", client_id=info.client_id, fingerprint=crypto.fingerprint(info.public_key))

    def _on_e2e(self, body: bytes) -> None:
        """Valida e decifra um frame E2E. Ordem importa: o estado (seq_recv, IV_base)
        só é atualizado DEPOIS que a tag GCM foi verificada."""
        try:
            f = protocol.parse_e2e(body)
        except ProtocolError:
            return self._reject("tamanho de frame E2E inválido")
        if f.recipient_id != self.client_id:
            return self._reject("frame endereçado a outro cliente", f.sender_id)
        peer = self.peers.get(f.sender_id)
        if peer is None:
            return self._reject("remetente desconhecido", f.sender_id)
        if f.nonce[protocol.IV_BASE_LEN:] != f.seq_bytes:
            return self._reject("nonce inconsistente com seq_no", f.sender_id)
        if peer.iv_base_recv is not None and f.nonce[:protocol.IV_BASE_LEN] != peer.iv_base_recv:
            return self._reject("IV_base diferente do da sessão", f.sender_id)
        try:
            plain = crypto.aead_open(peer.key_recv, f.nonce, f.ciphertext, f.aad)
        except crypto.AuthenticationError:
            return self._reject("tag GCM inválida (mensagem adulterada ou chave incorreta)", f.sender_id)
        if f.seq_no <= peer.seq_recv:
            return self._reject(f"replay detectado (seq_no {f.seq_no} já usado)", f.sender_id)
        # autenticada e nova: agora sim atualiza o estado
        peer.seq_recv = f.seq_no
        if peer.iv_base_recv is None:
            peer.iv_base_recv = f.nonce[:protocol.IV_BASE_LEN]
        text = plain.decode("utf-8", errors="replace")
        self.messages.append((f.sender_id, text))
        log.info("mensagem de %s recebida (%d bytes)", sid(f.sender_id), len(plain))
        self._emit("message", sender=f.sender_id, text=text)

    # ------------------------------------------------------------------ envio
    def resolve_peer(self, ref: str) -> Peer:
        """Aceita índice (1,2,...) ou prefixo hexadecimal do client_id."""
        if ref.isdigit():
            idx = int(ref)
            lst = list(self.peers.values())
            if 1 <= idx <= len(lst):
                return lst[idx - 1]
            raise KeyError(f"não existe peer #{idx}")
        ref = ref.lower().replace("-", "")
        found = [p for p in self.peers.values() if p.client_id.hex().startswith(ref)]
        if len(found) == 1:
            return found[0]
        raise KeyError("peer não encontrado" if not found else "prefixo ambíguo")

    def _build_e2e(self, peer: Peer, text: str) -> bytes:
        data = text.encode("utf-8")
        if len(data) > protocol.MAX_PLAINTEXT:
            raise ValueError(f"mensagem maior que {protocol.MAX_PLAINTEXT} bytes")
        seq = peer.seq_send
        if seq >= 2 ** 64:
            raise ValueError("seq_no esgotado: reconecte para gerar novas chaves")
        peer.seq_send = seq + 1        # incrementa ANTES de qualquer await: nonce nunca se repete
        seq_b = seq.to_bytes(protocol.SEQ_LEN, "big")
        nonce = crypto.make_nonce(peer.iv_base_send, seq)
        aad = protocol.e2e_aad(self.client_id, peer.client_id, seq_b)
        ct = crypto.aead_seal(peer.key_send, nonce, data, aad)
        return protocol.pack_e2e(nonce, self.client_id, peer.client_id, seq_b, ct)

    async def send_message(self, peer: Peer, text: str) -> None:
        body = self._build_e2e(peer, text)
        self._last_e2e = body
        await self._send_frame(protocol.T_E2E, body)

    async def send_tampered(self, peer: Peer, text: str) -> None:
        """DEMO: envia um frame com 1 bit do ciphertext invertido (o destinatário deve rejeitar)."""
        b = bytearray(self._build_e2e(peer, text))
        b[protocol.OFF_CT] ^= 0x01
        await self._send_frame(protocol.T_E2E, bytes(b))

    async def replay_last(self) -> None:
        """DEMO: reenvia exatamente o último frame E2E enviado (o destinatário deve rejeitar)."""
        if self._last_e2e is None:
            raise ValueError("ainda não há mensagem enviada para repetir")
        await self._send_frame(protocol.T_E2E, self._last_e2e)

    async def request_peer_list(self) -> None:
        await self._send_control(protocol.T_LIST_REQ)

    async def _send_frame(self, ftype: int, payload: bytes) -> None:
        if not self.connected or self.writer is None:
            raise ConnectionError("cliente desconectado")
        self.writer.write(framing.encode_frame(ftype, payload))
        await self._drain()

    async def _send_control(self, ftype: int) -> None:
        if not self.connected or self.writer is None or self.channel is None:
            raise ConnectionError("cliente desconectado")
        payload = self.channel.seal(ftype)             # seal+write síncronos (ordem dos seq_no)
        self.writer.write(framing.encode_frame(ftype, payload))
        await self._drain()

    async def _drain(self) -> None:
        assert self.writer is not None
        async with self._wlock:
            await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT)

    # ------------------------------------------------------------------ encerramento
    def _close_transport(self) -> None:
        if self.writer is not None and not self.writer.is_closing():
            self.writer.close()

    async def close(self) -> None:
        self._closing = True
        if self.connected:
            try:
                await self._send_control(protocol.T_BYE)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                pass
        self._close_transport()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, 2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self.connected = False
        # descarta estado de sessão
        self.peers.clear()


# ====================================================================== CLI
HELP = """\
Comandos:
  /peers                    lista os peers conectados (índice, id, fingerprint)
  /msg <peer> <texto>       envia mensagem E2E (peer = índice de /peers ou prefixo do id)
  /all <texto>              envia a mesma mensagem (cifrada separadamente) a todos os peers
  /fp                       mostra o seu id e o fingerprint da sua chave pública
  /refresh                  pede ao servidor a lista de peers novamente
  /tamper <peer> <texto>    DEMO: envia mensagem com 1 bit adulterado
  /replay                   DEMO: reenvia o último frame enviado
  /help                     esta ajuda
  /quit                     sair
"""


def _print_event(label: str):
    def handler(kind: str, **info) -> None:
        if kind == "message":
            print(f"\n<{sid(info['sender'])}> {info['text']}")
        elif kind == "peer_join":
            print(f"\n[+] peer {sid(info['client_id'])} entrou (fp {info['fingerprint']})")
        elif kind == "peer_leave":
            print(f"\n[-] peer {sid(info['client_id'])} saiu")
        elif kind == "reject":
            print(f"\n[!] mensagem rejeitada: {info['reason']}")
        elif kind == "server_error":
            from common.protocol import ERROR_TEXT, ERR_RECIPIENT_OFFLINE
            extra = f" ({sid(info['detail'])})" if info["code"] == ERR_RECIPIENT_OFFLINE else ""
            print(f"\n[!] servidor: {ERROR_TEXT.get(info['code'], info['code'])}{extra}")
        elif kind == "disconnected" and not info.get("local"):
            print(f"\n[x] {info['reason']}")
    return handler


def _stdin_reader(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue) -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return
        loop.call_soon_threadsafe(queue.put_nowait, line.rstrip("\n"))


async def run_cli(args: argparse.Namespace) -> int:
    try:
        pinned = certs.load_cert(args.cert)
    except (OSError, ValueError) as exc:
        print(f"[ERRO] não foi possível ler o certificado pinado '{args.cert}': {exc}")
        return 1
    client_id = None
    if args.client_id:
        try:
            client_id = uuid.UUID(args.client_id).bytes
        except ValueError:
            print("[ERRO] --client-id deve ser um UUID v4 válido")
            return 1
    try:
        client = SecureClient(args.host, args.port, pinned, client_id, on_event=_print_event(args.label))
    except ProtocolError as exc:
        print(f"[ERRO] {exc}")
        return 1
    try:
        await client.connect()
    except HandshakeError as exc:
        print(f"[ERRO] {exc}")
        return 1

    print(f"Conectado. Seu id: {cid(client.client_id)}")
    print(f"Fingerprint da sua chave pública: {crypto.fingerprint(client.public_key)}")
    print("Compare fingerprints com seus contatos por outro canal (detecta servidor malicioso).")
    print(HELP)

    queue: asyncio.Queue = asyncio.Queue()
    threading.Thread(target=_stdin_reader, args=(asyncio.get_running_loop(), queue), daemon=True).start()

    try:
        while True:
            getter = asyncio.ensure_future(queue.get())
            disc = asyncio.ensure_future(client.disconnected.wait())
            done, pending = await asyncio.wait({getter, disc}, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
            if disc in done:
                break
            line = getter.result()
            if line is None:
                await asyncio.sleep(0.5)      # EOF (entrada redirecionada): dá tempo de chegarem respostas
                break
            if not await _handle_command(client, line.strip()):
                break
    finally:
        await client.close()
    return 0


async def _handle_command(client: SecureClient, line: str) -> bool:
    if not line:
        return True
    cmd, _, rest = line.partition(" ")
    try:
        if cmd == "/quit":
            return False
        elif cmd == "/help":
            print(HELP)
        elif cmd == "/fp":
            print(f"id {cid(client.client_id)}  fp {crypto.fingerprint(client.public_key)}")
        elif cmd == "/peers":
            if not client.peers:
                print("(nenhum peer conectado)")
            for i, p in enumerate(client.peers.values(), 1):
                print(f"  {i}) {sid(p.client_id)}  fp {p.fingerprint}  enviadas={p.seq_send} "
                      f"recebidas={p.seq_recv + 1}")
        elif cmd == "/refresh":
            await client.request_peer_list()
        elif cmd in ("/msg", "/tamper"):
            ref, _, text = rest.partition(" ")
            if not ref or not text:
                print(f"uso: {cmd} <peer> <texto>")
            else:
                peer = client.resolve_peer(ref)
                if cmd == "/msg":
                    await client.send_message(peer, text)
                else:
                    await client.send_tampered(peer, text)
                    print("[demo] frame adulterado enviado")
        elif cmd == "/all":
            if not rest:
                print("uso: /all <texto>")
            for peer in list(client.peers.values()):
                await client.send_message(peer, rest)
        elif cmd == "/replay":
            await client.replay_last()
            print("[demo] último frame reenviado")
        else:
            print("comando desconhecido; use /help")
    except (KeyError, ValueError, ConnectionError) as exc:
        print(f"[ERRO] {exc}")
    return True


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cliente - mensageria segura E2E (TP3)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", default="certs/server.crt", help="certificado do servidor (PINADO)")
    p.add_argument("--client-id", help="UUID v4 a reutilizar (padrão: gera um novo)")
    p.add_argument("--label", default="", help="apelido local (apenas para você identificar o terminal)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    if not args.verbose:
        logging.getLogger().setLevel(logging.ERROR)     # CLI limpa: eventos importantes vão por print
    try:
        return asyncio.run(run_cli(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
