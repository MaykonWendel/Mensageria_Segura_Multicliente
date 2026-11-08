import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import certs  # noqa: E402
from server import RelayServer  # noqa: E402
from client import SecureClient  # noqa: E402


@pytest.fixture(scope="session")
def rsa_material():
    """Par RSA + certificado gerados uma única vez (a geração é lenta)."""
    key, cert = certs.generate_self_signed("tp3-test")
    return key, cert


@pytest.fixture(scope="session")
def other_cert():
    """Um segundo certificado, diferente do pinado (para testar pinning)."""
    return certs.generate_self_signed("impostor")


async def wait_until(cond, timeout=3.0, step=0.01):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if cond():
            return True
        await asyncio.sleep(step)
    return cond()


class Env:
    """Ambiente de teste: servidor em porta efêmera + fábrica de clientes."""

    def __init__(self, rsa_material, **server_kwargs):
        self.key, self.cert = rsa_material
        self.server = RelayServer(self.key, certs.cert_to_der(self.cert), port=0, **server_kwargs)
        self.clients = []

    async def __aenter__(self):
        self.port = await self.server.start()
        return self

    async def __aexit__(self, *exc):
        for c in self.clients:
            await c.close()
        await self.server.stop()

    async def client(self, cert=None, port=None, client_id=None):
        c = SecureClient("127.0.0.1", port or self.port, cert or self.cert, client_id=client_id)
        await c.connect()
        self.clients.append(c)
        return c

    async def pair(self):
        a, b = await self.client(), await self.client()
        assert await wait_until(lambda: b.client_id in a.peers and a.client_id in b.peers)
        return a, b
