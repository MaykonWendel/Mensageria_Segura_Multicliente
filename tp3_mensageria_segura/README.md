# TP3 — Sistema de Mensageria Segura Multi-Cliente (E2E)

Disciplina: Segurança da Informação — Prof. Michel Sales · UFC Campus Quixadá

Mensageria com criptografia ponta a ponta. O servidor é apenas um **relay**: autentica-se
perante os clientes, distribui as chaves públicas e repassa bytes cifrados que **não consegue
decifrar**.

| Garantia | Mecanismo |
|---|---|
| Confidencialidade | AES-128-GCM (AEAD) |
| Integridade | tag de autenticação do GCM (16 B) |
| Autenticidade do servidor | certificado RSA autoassinado **pinado** + assinatura RSA-PSS (SHA-256) do handshake |
| Sigilo perfeito (forward secrecy) | ECDHE com X25519 efêmero (o RSA só assina, nunca cifra/deriva chaves) |
| Anti-replay | `seq_no` monotônico por direção, verificado só depois da tag |

## 1. Como executar

Requisitos: Python 3.10+ (testado em 3.12) e `pip install -r requirements.txt`.

```bash
# 1) gerar chave e certificado do servidor (uma única vez)
python tools/gen_cert.py            # cria certs/server.key (privada) e certs/server.crt (pública)

# 2) servidor
python server.py --host 0.0.0.0 --port 8443

# 3) clientes (um terminal para cada); o certificado é "pinado" via --cert
python client.py --host 127.0.0.1 --port 8443 --cert certs/server.crt --label A
python client.py --host 127.0.0.1 --port 8443 --cert certs/server.crt --label B
```

Para rodar em computadores diferentes, copie **somente** `certs/server.crt` para os clientes
(idealmente por um canal confiável). `server.key` nunca sai do servidor.

Comandos do cliente: `/peers`, `/msg <índice|prefixo-do-id> <texto>`, `/all <texto>`, `/fp`,
`/refresh`, `/tamper`, `/replay`, `/help`, `/quit`.

Demonstração automática de todos os testes obrigatórios (sem precisar de vários terminais):

```bash
python demo.py        # 24 verificações; termina com código 0 se tudo passar
pytest -q             # 70 testes automatizados
```

## 2. Os testes obrigatórios, ao vivo

| Teste do enunciado | Como mostrar |
|---|---|
| 2+ clientes trocando mensagens E2E | 3 terminais de cliente; A→B funciona e C não recebe nada. Servidor com `--show-ciphertext` mostra só ciphertext. |
| Bitflip → rejeitado (tag GCM) | `/tamper 1 texto` no cliente, **ou** reinicie o servidor com `--demo-tamper` (relay malicioso que inverte 1 bit). |
| Replay → rejeitado (seq_no) | `/replay` no cliente, **ou** servidor com `--demo-replay` (repassa cada frame 2×). |
| Framing inválido → desconexão segura | `python tools/framing_attack.py --port 8443` (tamanho 0xFFFFFFFF, 0, lixo, tipo errado, HELLO malformado, `client_id` inválido). |
| Servidor não decifra | O servidor não tem nenhuma chave E2E (ver `Session` em `server.py`); o log só tem tamanhos e fingerprints. |

## 3. Protocolo

### 3.1 Framing

```
[ comprimento (4B big-endian) ][ tipo (1B) ][ payload ]     comprimento = 1 + len(payload)
```

O tamanho é validado **antes** de ler/alocar: `0` ou `> 4165` é erro de framing e a conexão é
encerrada. (4165 = tipo 1 + nonce 12 + sender 16 + recipient 16 + seq 8 + 4096 de texto + tag 16.)

| Tipo | Nome | Sentido | Conteúdo |
|---|---|---|---|
| `0x01` | HELLO | C→S (claro) | `client_id(16) ‖ pk_C(32)` |
| `0x02` | HELLO_REPLY | S→C (claro, assinado) | `pk_S(32) ‖ salt(16) ‖ len+assinatura ‖ len+server.crt` |
| `0x10` | REGISTER_ACK | S→C (controle) | — |
| `0x11` | PEER_INFO | S→C (controle) | `client_id(16) ‖ pk(32) ‖ salt(16)` |
| `0x12` | PEER_LEAVE | S→C (controle) | `client_id(16)` |
| `0x13` | ERROR | S→C (controle) | `código(1) ‖ detalhe` |
| `0x14` | LIST_REQ | C→S (controle) | — |
| `0x15` | BYE | C→S (controle) | — |
| `0x20` | E2E | C→S→C (relay) | frame E2E abaixo |

### 3.2 Handshake autenticado

```
Cliente                                              Servidor
  gera sk_C/pk_C (X25519 efêmero)
  ── HELLO: client_id ‖ pk_C ───────────────────────►
                                                      gera sk_S/pk_S (efêmero) e salt_srv (16B)
                                                      H = SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt)
                                                      sig = RSA-PSS(SHA-256) sobre H
  ◄── HELLO_REPLY: pk_S ‖ salt ‖ sig ‖ server.crt ───
  confere server.crt == certificado pinado
  verifica sig com a chave do cert PINADO
  Z = ECDH(sk_C, pk_S)                                Z = ECDH(sk_S, pk_C)
  PRK = HKDF-Extract(salt, Z)                         (idem)
  K_C2S, K_S2C = HKDF-Expand(PRK, "C2S"/"S2C", 16)    (idem)
  ◄── [controle] REGISTER_ACK ──────────────────────  registra client_id → sessions
  ◄── [controle] PEER_INFO (cada cliente já online) ─ e avisa os outros sobre o novo
```

Como `H` inclui `pk_C`, `client_id` e um `salt` novo, uma resposta antiga do servidor não pode
ser reaproveitada em outra conexão. Se o certificado ou a assinatura não conferirem, o cliente
aborta antes de usar qualquer dado do servidor.

### 3.3 Derivação das chaves E2E (par A↔B)

```
Z_AB      = ECDH(sk_A, pk_B)                       (nunca transmitido, descartado após derivar)
salt_par  = SHA256(salt_do_menor_id ‖ salt_do_maior_id)[:16]
PRK       = HKDF-Extract(salt_par, Z_AB)
Key_A2B   = HKDF-Expand(PRK, "A2B", 16)
Key_B2A   = HKDF-Expand(PRK, "B2A", 16)
```

"A" é o cliente com o **menor `client_id`** (comparação de bytes). A envia com `Key_A2B` e recebe
com `Key_B2A`; B faz o inverso. Assim, as duas pontas concordam sem negociação.

### 3.4 Frame E2E

```
[ nonce (12B) ][ sender_id (16B) ][ recipient_id (16B) ][ seq_no (8B) ][ ciphertext ‖ tag (16B) ]

nonce = IV_base (4B aleatório por direção/sessão) ‖ seq_no (8B big-endian)
AAD   = sender_id ‖ recipient_id ‖ seq_no
```

**Envio:** `seq = seq_send; seq_send += 1` (primeira mensagem tem `seq_no = 0`), cifra, envia.

**Recepção (a ordem importa):**
1. tamanho válido e `recipient_id` é o meu;
2. `sender_id` é um peer conhecido;
3. `nonce[4:12] == seq_no` e `IV_base` igual ao já aprendido nesta sessão (se houver);
4. decifra + verifica a tag GCM → falha = **adulteração**;
5. `seq_no > seq_recv` → senão = **replay**;
6. **só agora** atualiza `seq_recv` (e guarda o `IV_base` na primeira mensagem).

Atualizar o estado antes de autenticar permitiria que um atacante "queimasse" números de
sequência com frames forjados e bloqueasse mensagens legítimas.

### 3.5 Canal de controle servidor↔cliente

Mensagens administrativas (ACK, lista de peers, saída de peers, erros) usam AES-128-GCM com as
chaves `C2S`/`S2C`, `nonce = direção (4B: 0=c2s, 1=s2c) ‖ seq_no (8B)` e AAD = `tipo ‖ seq_no`.
É aqui que `seq_send`/`seq_recv` da tabela `sessions` são usados. Frames de controle repetidos,
adulterados ou fora de ordem fazem o servidor encerrar a conexão. Este canal **não** carrega
mensagens E2E.

## 4. Decisões de projeto (pontos em aberto no enunciado)

1. **`pk_S` no hash `H`** é a chave **X25519 efêmera do servidor** (32 B, nova a cada conexão). O RSA
   apenas assina; é isso que mantém o sigilo perfeito mesmo se o RSA vazar depois.
2. **Canal de controle:** derivado de `ECDH(sk_C, pk_S)` com `salt_srv` e labels `"C2S"`/`"S2C"`.
3. **Salt do par A↔B:** cada cliente tem seu `salt_srv`; o servidor entrega o salt de cada peer
   junto com a `pk`, e ambos calculam o mesmo `salt_par` (§3.3).
4. **`IV_base`:** aleatório de 4 B por direção, enviado no próprio campo `nonce`. O receptor o
   aprende na primeira mensagem **autenticada** e exige que não mude. Como cada direção tem sua
   própria chave e o `seq_no` nunca repete, o nonce nunca se repete sob a mesma chave.
5. **Assinatura:** `H` (32 B) é assinado com RSA-PSS (MGF1-SHA256, salt de 32 B) usando o digest
   já calculado (`Prehashed`), ou seja, é equivalente a assinar o material com RSA-PSS(SHA-256).
6. **Byte de tipo** após o prefixo de tamanho, para distinguir handshake, controle e E2E.
7. **`client_id`** precisa ser UUID v4; `client_id` duplicado enquanto conectado é recusado.
8. **Limite de texto claro: 4096 bytes** (cabe em um único frame de 4165 B, evita fragmentação e
   limita memória por conexão). Validado no envio, no relay e na recepção.
9. **Limites de recursos:** `--max-clients` (padrão 100), timeout de handshake (10 s), timeout de
   corpo de frame (30 s) e desconexão de clientes que não drenam a escrita (10 s).

## 5. Estruturas de dados

**Servidor** — `RelayServer.sessions: dict[client_id → Session]`

| Campo | Significado |
|---|---|
| `writer` | `StreamWriter` da conexão |
| `public_key` | `pk_C` (32 B) |
| `salt` | `salt_srv` (16 B) |
| `seq_recv` / `seq_send` | contadores do canal de controle (`-1` e `0` no início) |
| chaves `C2S`/`S2C` | só do canal de controle; **nenhuma chave E2E** |

**Cliente** — `SecureClient.peers: dict[client_id → Peer]`

| Campo | Significado |
|---|---|
| `public_key` | `pk` do peer |
| `key_send` / `key_recv` | `Key_A2B`/`Key_B2A` (ou o inverso, conforme a regra A/B) |
| `seq_send` / `seq_recv` | `0` / `-1` no início |
| `iv_base_send` / `iv_base_recv` | IV_base por direção |
| `Z_AB` | **não é armazenado** (descartado após a derivação) |

## 6. Política de logs

Permitido: conexão/desconexão, `client_id`, tamanhos, motivo de rejeição (ex.: "tag GCM
inválida", "replay detectado") e fingerprints de chaves públicas.
Proibido: chaves privadas, `Z`, chaves derivadas, `salt`, nonces e conteúdo de mensagens.

Como defesa em profundidade, `common/log_utils.py` instala um filtro que **bloqueia qualquer log
com argumento `bytes`**; `tests/test_log_policy.py` roda uma sessão completa e confere que
nenhum segredo, salt, nonce ou texto claro aparece nos logs. A flag `--show-ciphertext` (apenas
demo) mostra o início do *ciphertext* para provar que ele é ilegível; nunca nonce, chave ou texto
claro. O `server.key` é criado com permissão `0600` e está no `.gitignore`.

## 7. Limitações conhecidas (para discutir na apresentação)

- **Servidor malicioso na distribuição de chaves:** como o servidor entrega as `pk` dos clientes, ele
  poderia trocá-las e fazer MITM entre A e B. A mitigação é comparar **fingerprints** por outro
  canal (`/fp` e `/peers` mostram). O enunciado define esta arquitetura.
- **`client_id` não é autenticado** (o enunciado não prevê autenticação de clientes).
- **Não há irretratabilidade:** a chave simétrica é compartilhada pelos dois lados.
- **Metadados visíveis ao servidor:** quem fala com quem, quando e o tamanho dos frames.
- **Sem rotação de chaves** (opcional no enunciado). Reconectar gera chaves novas; `seq_no` de 64 bits
  é validado contra estouro.
- Python não garante apagar segredos da memória; o código apenas descarta as referências (`del Z`).

## 8. Estrutura do projeto e mapa da rubrica

```
server.py            servidor relay (handshake, sessions, relay, controle)
client.py            SecureClient (protocolo) + CLI interativa
common/
  protocol.py        constantes, tipos de frame, formatos e parsers
  framing.py         prefixo de tamanho de 4 B e validações
  crypto.py          X25519, HKDF (RFC 5869), AES-128-GCM, RSA-PSS, nonce
  channel.py         canal de controle servidor↔cliente (AES-GCM + seq_no)
  certs.py           geração/carga do certificado autoassinado
  log_utils.py       política de logs e filtro anti-segredo
tools/               gen_cert.py, framing_attack.py
tests/               70 testes (cripto, framing, logs, integração/ataques)
demo.py              demonstração automática dos testes obrigatórios
docs/                roteiro da apresentação e perguntas prováveis
```

| Rubrica | Onde está |
|---|---|
| Handshake e rendezvous E2E (30%) | `server._handshake`, `server._register`, `client._handshake`, `client._add_peer`, `client.derive_e2e_keys` |
| AES-GCM E2E, nonce e seq_no (25%) | `client._build_e2e`, `client._on_e2e`, `crypto.aead_*`, `crypto.make_nonce` |
| Replay e tampering (20%) | `client._on_e2e`; `demo.py` (testes 2 e 3); `tests/test_integration.py` |
| Código, documentação e demo (15%) | este README, `docs/`, `demo.py`, `pytest` |
| Práticas de segurança (10%) | `common/log_utils.py`, `tests/test_log_policy.py`, `.gitignore`, `certs.save_key` (0600) |
