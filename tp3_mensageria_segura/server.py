#!/usr/bin/env python3
"""Servidor relay do TP3 - Mensageria Segura Multi-Cliente (E2E).

O servidor:
  * autentica-se perante cada cliente (RSA-PSS sobre H = SHA256(pk_S||pk_C||client_id||salt));
  * registra client_id + pk_C na tabela `sessions` e distribui as chaves públicas;
  * repassa frames E2E SEM decifrar (não possui nenhuma chave E2E);
  * mantém um canal de controle próprio (AES-GCM + seq_no) para mensagens administrativas.

Uso:
    python server.py --key certs/server.key --cert certs/server.crt --port 8443
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Callable, Optional

from common import certs, crypto, framing, protocol
from common.channel import DIR_C2S, DIR_S2C, ChannelError, ControlChannel
from common.framing import FramingError
from common.log_utils import cid, setup_logging, sid
from common.protocol import ProtocolError

log = logging.getLogger("server")

HANDSHAKE_TIMEOUT = 10.0   # segundos para o cliente completar o HELLO
WRITE_TIMEOUT = 10.0       # cliente lento demais é desconectado
HELLO_FRAME_LEN = 1 + protocol.ID_LEN + protocol.PK_LEN   # tipo + client_id + pk_C


class Session:
    """Entrada da tabela `sessions` (uma por cliente conectado).

    Campos do enunciado: writer, public_key, seq_recv, seq_send, salt.
    Os contadores vivem no ControlChannel (canal servidor<->cliente).
    O servidor NÃO guarda nada que permita decifrar mensagens cliente->cliente.
    """

    def __init__(self, client_id: bytes, writer: asyncio.StreamWriter,
                 public_key: bytes, salt: bytes, channel: ControlChannel):
        self.client_id = client_id
        self.writer = writer
        self.public_key = public_key      # pk_C (32B)
        self.salt = salt                  # salt_srv (16B)
        self.channel = channel
        self._lock = asyncio.Lock()
        self.closed = False

    @property
    def seq_send(self) -> int:   # próximo seq_no de controle enviado pelo servidor
        return self.channel.seq_send

    @property
    def seq_recv(self) -> int:   # último seq_no de controle recebido do cliente
        return self.channel.seq_recv

    def peer_info(self) -> bytes:
        return protocol.pack_peer_info(self.client_id, self.public_key, self.salt)

    async def send_control(self, ftype: int, plaintext: bytes = b"") -> None:
        if self.closed or self.writer.is_closing():
            return
        # seal + write são síncronos: a ordem dos seq_no coincide com a ordem no socket
        payload = self.channel.seal(ftype, plaintext)
        self.writer.write(framing.encode_frame(ftype, payload))
        await self._drain()

    async def send_raw(self, ftype: int, payload: bytes) -> None:
        """Usado no relay E2E: bytes repassados sem interpretação."""
        if self.closed or self.writer.is_closing():
            return
        self.writer.write(framing.encode_frame(ftype, payload))
        await self._drain()

    async def _drain(self) -> None:
        try:
            async with self._lock:
                await asyncio.wait_for(self.writer.drain(), WRITE_TIMEOUT)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            log.warning("falha ao escrever para %s; encerrando conexão", sid(self.client_id))
            self.abort()

    def abort(self) -> None:
        self.closed = True
        transport = self.writer.transport
        if transport is not None:
            transport.abort()


class RelayServer:
    def __init__(self, rsa_key, cert_der: bytes, host: str = "127.0.0.1", port: int = 8443,
                 max_clients: int = 100, demo_tamper: bool = False, demo_replay: bool = False,
                 show_ciphertext: bool = False,
                 relay_hook: Optional[Callable[[bytes], None]] = None):
        self._rsa_key = rsa_key
        self._cert_der = cert_der
        self.host = host
        self.port = port
        self.max_clients = max_clients
        # Modos de DEMONSTRAÇÃO: simulam um atacante no caminho (o relay malicioso).
        self.demo_tamper = demo_tamper
        self.demo_replay = demo_replay
        self.show_ciphertext = show_ciphertext
        self.relay_hook = relay_hook          # usado nos testes para observar os bytes repassados
        self.sessions: dict[bytes, Session] = {}
        self._connections = 0
        self._server: Optional[asyncio.AbstractServer] = None

    @classmethod
    def from_files(cls, key_path: str, cert_path: str, **kwargs) -> "RelayServer":
        key = certs.load_key(key_path)
        cert = certs.load_cert(cert_path)
        if not certs.key_matches_cert(key, cert):
            raise ValueError("a chave privada não corresponde ao certificado")
        return cls(key, certs.cert_to_der(cert), **kwargs)

    # ------------------------------------------------------------------ ciclo de vida
    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("servidor ouvindo em %s:%d (máx. %d clientes)", self.host, self.port, self.max_clients)
        return self.port

    async def serve_forever(self) -> None:
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for s in list(self.sessions.values()):
            s.abort()
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 2.0)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------ conexão
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        session: Optional[Session] = None
        registered = False
        if self._connections >= self.max_clients:
            log.warning("limite de %d conexões atingido; recusando %s", self.max_clients, addr)
            writer.close()
            return
        self._connections += 1
        try:
            session = await self._handshake(reader, writer, addr)
            if session is None:
                return
            registered = await self._register(session)
            if not registered:
                return
            await self._serve_session(reader, session)
        except (FramingError, ProtocolError, ChannelError) as exc:
            log.warning("conexão %s encerrada: %s", sid(session.client_id) if session else addr, exc)
            if session is not None and registered:
                code = protocol.ERR_BAD_FRAME
                await session.send_control(protocol.T_ERROR, protocol.pack_error(code, str(exc).encode()[:100]))
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, OSError):
            log.info("conexão %s encerrada pelo cliente", sid(session.client_id) if session else addr)
        except Exception:  # bug inesperado: nunca derrubar o servidor por causa de um cliente
            log.exception("erro interno na conexão %s", sid(session.client_id) if session else addr)
        finally:
            self._connections -= 1
            if session is not None and registered:
                await self._unregister(session)
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------ handshake
    async def _handshake(self, reader, writer, addr) -> Optional[Session]:
        try:
            ftype, payload = await asyncio.wait_for(
                framing.read_frame(reader, max_len=HELLO_FRAME_LEN), HANDSHAKE_TIMEOUT)
            if ftype != protocol.T_HELLO:
                raise ProtocolError("o primeiro frame deve ser HELLO")
            client_id, pk_c = protocol.parse_hello(payload)
            protocol.check_uuid4(client_id)
        except (FramingError, ProtocolError) as exc:
            log.warning("handshake rejeitado de %s: %s", addr, exc)
            return None
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            log.info("handshake incompleto de %s", addr)
            return None

        # par efêmero do servidor: é isto que garante o sigilo perfeito (RSA só assina)
        sk_s, pk_s = crypto.generate_x25519()
        try:
            z = crypto.x25519_exchange(sk_s, pk_c)
        except crypto.CryptoError:
            log.warning("handshake rejeitado de %s: chave pública X25519 inválida", addr)
            return None
        salt = os.urandom(protocol.SALT_LEN)
        h = crypto.handshake_hash(pk_s, pk_c, client_id, salt)
        signature = crypto.rsa_pss_sign(self._rsa_key, h)

        writer.write(framing.encode_frame(
            protocol.T_HELLO_REPLY, protocol.pack_hello_reply(pk_s, salt, signature, self._cert_der)))
        await asyncio.wait_for(writer.drain(), WRITE_TIMEOUT)

        prk = crypto.hkdf_extract(salt, z)
        k_c2s = crypto.hkdf_expand(prk, b"C2S", protocol.KEY_LEN)
        k_s2c = crypto.hkdf_expand(prk, b"S2C", protocol.KEY_LEN)
        del z, prk, sk_s   # o segredo ECDH não é mantido
        channel = ControlChannel(key_send=k_s2c, key_recv=k_c2s, dir_send=DIR_S2C, dir_recv=DIR_C2S)
        log.info("handshake concluído com %s (%s) fp=%s", sid(client_id), addr, crypto.fingerprint(pk_c))
        return Session(client_id, writer, pk_c, salt, channel)

    # ------------------------------------------------------------------ registro / peers
    async def _register(self, session: Session) -> bool:
        if session.client_id in self.sessions:
            log.warning("client_id %s já conectado; recusando", sid(session.client_id))
            await session.send_control(protocol.T_ERROR, protocol.pack_error(protocol.ERR_DUPLICATE_ID))
            return False
        existing = list(self.sessions.values())
        self.sessions[session.client_id] = session   # sem await entre checagem e inserção
        # seal+write do ACK ocorrem antes de qualquer outra tarefa rodar: o ACK é o 1º frame de controle
        await session.send_control(protocol.T_REGISTER_ACK)
        log.info("registrado %s (%s); %d cliente(s) online", sid(session.client_id),
                 cid(session.client_id), len(self.sessions))
        # o novo recebe os existentes; os existentes recebem o novo
        for other in existing:
            await session.send_control(protocol.T_PEER_INFO, other.peer_info())
        await asyncio.gather(*(o.send_control(protocol.T_PEER_INFO, session.peer_info())
                               for o in existing), return_exceptions=True)
        return True

    async def _unregister(self, session: Session) -> None:
        if self.sessions.get(session.client_id) is session:
            del self.sessions[session.client_id]   # sessão em memória limpa
            log.info("desconectado %s; %d cliente(s) online", sid(session.client_id), len(self.sessions))
            others = list(self.sessions.values())
            await asyncio.gather(*(o.send_control(protocol.T_PEER_LEAVE, session.client_id)
                                   for o in others), return_exceptions=True)
        session.closed = True

    # ------------------------------------------------------------------ laço principal
    async def _serve_session(self, reader: asyncio.StreamReader, session: Session) -> None:
        while True:
            ftype, payload = await framing.read_frame(reader)
            if ftype == protocol.T_E2E:
                await self._relay(session, payload)
            elif ftype in protocol.CONTROL_C2S:
                session.channel.open(ftype, payload)       # autentica + anti-replay
                if ftype == protocol.T_BYE:
                    log.info("cliente %s pediu encerramento", sid(session.client_id))
                    return
                await self._send_peer_list(session)
            else:
                raise ProtocolError(f"tipo de frame inesperado: 0x{ftype:02x}")

    async def _send_peer_list(self, session: Session) -> None:
        for other in list(self.sessions.values()):
            if other is not session:
                await session.send_control(protocol.T_PEER_INFO, other.peer_info())

    # ------------------------------------------------------------------ relay E2E
    async def _relay(self, sender: Session, body: bytes) -> None:
        """Repassa um frame E2E. O servidor só lê sender_id e recipient_id (para rotear)."""
        n = len(body)
        if not protocol.E2E_MIN_LEN <= n <= protocol.E2E_MAX_LEN:
            raise FramingError(f"frame E2E com tamanho inválido ({n} bytes)")
        sender_id = body[protocol.OFF_SENDER:protocol.OFF_RECIPIENT]
        recipient_id = body[protocol.OFF_RECIPIENT:protocol.OFF_SEQ]

        if sender_id != sender.client_id:
            log.warning("rejeitado: sender_id do frame difere do client_id autenticado (%s)", sid(sender.client_id))
            await sender.send_control(protocol.T_ERROR, protocol.pack_error(protocol.ERR_BAD_SENDER))
            return
        dest = self.sessions.get(recipient_id)
        if dest is None:
            log.info("destinatário %s offline; frame de %d bytes descartado", sid(recipient_id), n)
            await sender.send_control(protocol.T_ERROR,
                                      protocol.pack_error(protocol.ERR_RECIPIENT_OFFLINE, recipient_id))
            return

        out = body
        if self.demo_tamper:
            out = self._flip_bit(body)
            log.warning("[DEMO] relay malicioso: 1 bit do ciphertext invertido")
        if self.relay_hook is not None:
            self.relay_hook(body)
        if self.show_ciphertext:   # DEMO: mostra só o ciphertext (nunca nonce/chaves/texto claro)
            log.info("[DEMO] ciphertext repassado (início): %s...", body[protocol.OFF_CT:protocol.OFF_CT + 16].hex())
        log.info("relay %s -> %s (%d bytes)", sid(sender.client_id), sid(dest.client_id), n)
        await dest.send_raw(protocol.T_E2E, out)
        if self.demo_replay:
            log.warning("[DEMO] relay malicioso: frame reenviado (replay)")
            await dest.send_raw(protocol.T_E2E, out)

    @staticmethod
    def _flip_bit(body: bytes) -> bytes:
        b = bytearray(body)
        b[protocol.OFF_CT] ^= 0x01     # primeiro byte do ciphertext
        return bytes(b)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Servidor relay - mensageria segura E2E (TP3)")
    p.add_argument("--host", default="127.0.0.1", help="endereço de escuta (use 0.0.0.0 para a rede)")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--key", default="certs/server.key", help="chave privada RSA do servidor (PEM)")
    p.add_argument("--cert", default="certs/server.crt", help="certificado autoassinado (PEM)")
    p.add_argument("--max-clients", type=int, default=100)
    p.add_argument("--demo-tamper", action="store_true", help="DEMO: inverte 1 bit de cada frame repassado")
    p.add_argument("--demo-replay", action="store_true", help="DEMO: repassa cada frame duas vezes")
    p.add_argument("--show-ciphertext", action="store_true",
                   help="DEMO: loga o início do ciphertext para provar que é ilegível")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    try:
        server = RelayServer.from_files(args.key, args.cert, host=args.host, port=args.port,
                                        max_clients=args.max_clients, demo_tamper=args.demo_tamper,
                                        demo_replay=args.demo_replay, show_ciphertext=args.show_ciphertext)
    except (OSError, ValueError) as exc:
        print(f"[ERRO] não foi possível carregar chave/certificado: {exc}\n"
              f"       gere-os com: python tools/gen_cert.py", file=sys.stderr)
        return 1
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        log.info("servidor encerrado")
    except OSError as exc:
        print(f"[ERRO] não foi possível abrir {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
