"""Testes unitários das primitivas criptográficas."""
import os

import pytest

from common import crypto
from common.channel import ChannelError, ControlChannel, DIR_C2S, DIR_S2C


# ---- HKDF: vetores oficiais da RFC 5869 --------------------------------------------------
def test_hkdf_rfc5869_case1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = crypto.hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = crypto.hkdf_expand(prk, info, 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_hkdf_rfc5869_case3_empty_salt_and_info():
    prk = crypto.hkdf_extract(b"", bytes.fromhex("0b" * 22))
    assert prk.hex() == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    assert crypto.hkdf_expand(prk, b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")


def test_hkdf_labels_give_different_keys():
    prk = crypto.hkdf_extract(os.urandom(16), os.urandom(32))
    assert crypto.hkdf_expand(prk, b"A2B", 16) != crypto.hkdf_expand(prk, b"B2A", 16)
    assert len(crypto.hkdf_expand(prk, b"A2B", 16)) == 16


# ---- X25519 --------------------------------------------------------------------------------
def test_x25519_both_sides_agree_and_pk_is_32_bytes_raw():
    sk_a, pk_a = crypto.generate_x25519()
    sk_b, pk_b = crypto.generate_x25519()
    assert len(pk_a) == len(pk_b) == 32
    assert crypto.x25519_exchange(sk_a, pk_b) == crypto.x25519_exchange(sk_b, pk_a)


def test_x25519_rejects_bad_public_keys():
    sk, _ = crypto.generate_x25519()
    with pytest.raises(crypto.CryptoError):
        crypto.x25519_exchange(sk, b"\x01" * 31)          # tamanho errado
    with pytest.raises(crypto.CryptoError):
        crypto.x25519_exchange(sk, bytes(32))             # ponto de ordem baixa


def test_ephemeral_keys_differ_each_time():
    assert crypto.generate_x25519()[1] != crypto.generate_x25519()[1]


# ---- AES-128-GCM ---------------------------------------------------------------------------
def test_aead_roundtrip_and_tag_is_appended():
    key, nonce, aad = os.urandom(16), os.urandom(12), b"aad"
    ct = crypto.aead_seal(key, nonce, b"mensagem secreta", aad)
    assert len(ct) == len(b"mensagem secreta") + 16
    assert b"mensagem secreta" not in ct
    assert crypto.aead_open(key, nonce, ct, aad) == b"mensagem secreta"


def test_aead_detects_bitflip_in_ciphertext_and_tag():
    key, nonce = os.urandom(16), os.urandom(12)
    ct = bytearray(crypto.aead_seal(key, nonce, b"abc", b""))
    for idx in (0, len(ct) - 1):          # ciphertext e tag
        bad = bytearray(ct)
        bad[idx] ^= 1
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_open(key, nonce, bytes(bad), b"")


def test_aead_detects_aad_change():
    key, nonce = os.urandom(16), os.urandom(12)
    ct = crypto.aead_seal(key, nonce, b"abc", b"sender|recipient|seq0")
    with pytest.raises(crypto.AuthenticationError):
        crypto.aead_open(key, nonce, ct, b"sender|recipient|seq1")


def test_aead_wrong_key_or_sizes():
    nonce = os.urandom(12)
    ct = crypto.aead_seal(os.urandom(16), nonce, b"x", b"")
    with pytest.raises(crypto.AuthenticationError):
        crypto.aead_open(os.urandom(16), nonce, ct, b"")
    with pytest.raises(crypto.CryptoError):
        crypto.aead_seal(os.urandom(32), nonce, b"x", b"")       # só AES-128
    with pytest.raises(crypto.CryptoError):
        crypto.aead_seal(os.urandom(16), os.urandom(8), b"x", b"")


def test_nonce_construction_big_endian():
    n = crypto.make_nonce(b"\xaa\xbb\xcc\xdd", 258)
    assert n == b"\xaa\xbb\xcc\xdd" + (258).to_bytes(8, "big") and len(n) == 12
    with pytest.raises(crypto.CryptoError):
        crypto.make_nonce(b"\x00" * 3, 1)


# ---- RSA-PSS -------------------------------------------------------------------------------
def test_rsa_pss_sign_verify_and_tamper(rsa_material):
    key, _ = rsa_material
    pk_s, pk_c, cid, salt = os.urandom(32), os.urandom(32), os.urandom(16), os.urandom(16)
    h = crypto.handshake_hash(pk_s, pk_c, cid, salt)
    sig = crypto.rsa_pss_sign(key, h)
    pub = key.public_key()
    assert crypto.rsa_pss_verify(pub, sig, h)
    # qualquer campo trocado muda H e invalida a assinatura
    assert not crypto.rsa_pss_verify(pub, sig, crypto.handshake_hash(os.urandom(32), pk_c, cid, salt))
    assert not crypto.rsa_pss_verify(pub, sig, crypto.handshake_hash(pk_s, os.urandom(32), cid, salt))
    assert not crypto.rsa_pss_verify(pub, sig, crypto.handshake_hash(pk_s, pk_c, os.urandom(16), salt))
    assert not crypto.rsa_pss_verify(pub, sig, crypto.handshake_hash(pk_s, pk_c, cid, os.urandom(16)))
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not crypto.rsa_pss_verify(pub, bytes(bad), h)


def test_rsa_pss_is_randomized(rsa_material):
    key, _ = rsa_material
    h = os.urandom(32)
    assert crypto.rsa_pss_sign(key, h) != crypto.rsa_pss_sign(key, h)   # salt aleatório do PSS


def test_handshake_hash_is_sha256_of_concatenation():
    import hashlib
    a, b, c, d = os.urandom(32), os.urandom(32), os.urandom(16), os.urandom(16)
    assert crypto.handshake_hash(a, b, c, d) == hashlib.sha256(a + b + c + d).digest()


# ---- Canal de controle ---------------------------------------------------------------------
def _channels():
    k1, k2 = os.urandom(16), os.urandom(16)
    cli = ControlChannel(k1, k2, DIR_C2S, DIR_S2C)
    srv = ControlChannel(k2, k1, DIR_S2C, DIR_C2S)
    return cli, srv


def test_control_channel_roundtrip_and_counters():
    cli, srv = _channels()
    assert (cli.seq_send, srv.seq_recv) == (0, -1)
    p = cli.seal(0x14, b"")
    assert srv.open(0x14, p) == b""
    assert (cli.seq_send, srv.seq_recv) == (1, 0)


def test_control_channel_rejects_replay_tamper_and_wrong_type():
    cli, srv = _channels()
    p = cli.seal(0x14, b"")
    srv.open(0x14, p)
    with pytest.raises(ChannelError):            # replay do mesmo frame
        srv.open(0x14, p)
    p2 = cli.seal(0x14, b"")
    bad = bytearray(p2)
    bad[-1] ^= 1
    with pytest.raises(ChannelError):            # adulteração
        srv.open(0x14, bytes(bad))
    with pytest.raises(ChannelError):            # tipo diferente (AAD inclui o tipo)
        srv.open(0x15, p2)
    assert srv.seq_recv == 0                     # estado intacto após as rejeições
    assert srv.open(0x14, p2) == b""             # frame legítimo ainda é aceito


def test_control_channel_direction_separation():
    cli, _ = _channels()
    p = cli.seal(0x14, b"")
    with pytest.raises(ChannelError):            # um frame c2s não é aceito como s2c (reflexão)
        cli.open(0x14, p)


# ---- AAD e formato do frame E2E (conforme o enunciado) ------------------------------------------
def test_aad_is_sender_recipient_seq_in_that_order():
    from common import protocol
    s, r, q = os.urandom(16), os.urandom(16), (7).to_bytes(8, "big")
    assert protocol.e2e_aad(s, r, q) == s + r + q


def test_e2e_frame_layout_matches_spec():
    from common import protocol
    n, s, r, q, ct = os.urandom(12), os.urandom(16), os.urandom(16), (3).to_bytes(8, "big"), os.urandom(20)
    body = protocol.pack_e2e(n, s, r, q, ct)
    assert body == n + s + r + q + ct          # [nonce][sender][recipient][seq][ciphertext+tag]
    f = protocol.parse_e2e(body)
    assert (f.nonce, f.sender_id, f.recipient_id, f.seq_bytes, f.ciphertext) == (n, s, r, q, ct)
    assert f.seq_no == 3 and f.aad == s + r + q
