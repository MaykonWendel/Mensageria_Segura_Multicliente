"""Framing: prefixo de 4 bytes big-endian, limites e tratamento de erro."""
import asyncio

import pytest

from common import framing, protocol


def feed(data: bytes, eof=True) -> asyncio.StreamReader:
    """Cria um StreamReader (precisa de um loop em execução)."""
    r = asyncio.StreamReader()
    r.feed_data(data)
    if eof:
        r.feed_eof()
    return r


def read_one(data: bytes, **kwargs):
    async def go():
        return await framing.read_frame(feed(data), **kwargs)
    return asyncio.run(go())


def test_encode_decode_roundtrip():
    raw = framing.encode_frame(protocol.T_E2E, b"abc")
    assert raw[:4] == (4).to_bytes(4, "big") and raw[4] == protocol.T_E2E
    ftype, payload = read_one(raw)
    assert (ftype, payload) == (protocol.T_E2E, b"abc")


def test_max_frame_matches_spec():
    # nonce 12 + sender 16 + recipient 16 + seq 8 + 4096 + tag 16 + tipo 1
    assert framing.MAX_FRAME_BODY == 12 + 16 + 16 + 8 + 4096 + 16 + 1 == 4165


@pytest.mark.parametrize("n", [0, framing.MAX_FRAME_BODY + 1, 0xFFFFFFFF])
def test_invalid_length_is_framing_error(n):
    with pytest.raises(framing.FramingError):
        read_one(n.to_bytes(4, "big") + b"x" * 10)


def test_truncated_frame_is_incomplete_read():
    with pytest.raises(asyncio.IncompleteReadError):
        read_one((50).to_bytes(4, "big") + b"x" * 10)


def test_slow_body_times_out():
    async def go():
        r = feed((50).to_bytes(4, "big") + b"x" * 10, eof=False)   # corpo nunca completa
        await framing.read_frame(r, body_timeout=0.2)
    with pytest.raises(framing.FramingError):
        asyncio.run(go())


def test_two_frames_back_to_back():
    raw = framing.encode_frame(1, b"aa") + framing.encode_frame(2, b"bbb")

    async def go():
        r = feed(raw)
        return await framing.read_frame(r), await framing.read_frame(r)
    assert asyncio.run(go()) == ((1, b"aa"), (2, b"bbb"))


def test_cannot_encode_oversized_frame():
    with pytest.raises(framing.FramingError):
        framing.encode_frame(protocol.T_E2E, b"x" * framing.MAX_FRAME_BODY)


def test_protocol_parsers_reject_bad_sizes():
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_hello(b"x" * 47)
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_e2e(b"x" * (protocol.E2E_MIN_LEN - 1))
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_e2e(b"x" * (protocol.E2E_MAX_LEN + 1))
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_hello_reply(b"x" * 10)
    with pytest.raises(protocol.ProtocolError):
        protocol.check_uuid4(b"\x00" * 16)          # não é UUID v4
