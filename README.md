# Mensageria Segura Multi-Cliente (E2E)

Sistema de mensagens com **criptografia ponta a ponta** em Python. O servidor funciona apenas como *relay*: ele se autentica perante os clientes, distribui as chaves públicas e repassa bytes cifrados que **não consegue decifrar**.

Trabalho Prático 3 da disciplina de **Segurança da Informação** (Prof. Michel Sales).

**Autores:** _<Maykon_Wendel>_ e _<Francisco_Riquelme>_

## Garantias de segurança

| Garantia | Mecanismo |
|---|---|
| Confidencialidade | AES-128-GCM (AEAD) |
| Integridade | Tag de autenticação do GCM (16 bytes) |
| Autenticidade do servidor | Certificado RSA autoassinado **pinado** + assinatura RSA-PSS (SHA-256) do handshake |
| Sigilo perfeito (*forward secrecy*) | ECDHE com X25519 efêmero (o RSA só assina, nunca deriva chaves) |
| Anti-replay | `seq_no` monotônico por direção, verificado somente depois da tag |

## Como funciona

O sistema tem três camadas:

1. **Handshake cliente↔servidor.** O cliente confirma a identidade do servidor antes de confiar em qualquer chave recebida.
2. **Canal de controle servidor↔cliente.** Mensagens administrativas (confirmação de registro, lista de peers, avisos de saída, erros), cifradas com AES-GCM e protegidas contra replay.
3. **Canal E2E cliente↔cliente.** Os clientes derivam chaves AES-128-GCM a partir de um ECDH entre eles. O servidor só repassa os bytes.

### Handshake autenticado

```
Cliente                                              Servidor
  gera par X25519 efêmero (sk_C, pk_C)
  ── HELLO: client_id ‖ pk_C ───────────────────────►
                                                      gera par efêmero (sk_S, pk_S) e salt_srv (16 B)
                                                      H   = SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt)
                                                      sig = RSA-PSS(SHA-256) sobre H
  ◄── HELLO_REPLY: pk_S ‖ salt ‖ sig ‖ server.crt ───
  confere server.crt == certificado pinado
  verifica sig com a chave do certificado PINADO
  deriva as chaves do canal de controle (C2S / S2C)
  ◄── [controle] REGISTER_ACK e PEER_INFO ──────────
```

O `H` inclui `pk_C`, `client_id` e um `salt` novo, então uma resposta antiga do servidor não pode ser reaproveitada em outra conexão. Se o certificado ou a assinatura não conferirem, o cliente aborta.

### Derivação das chaves E2E (par A↔B)

```
Z_AB      = ECDH(sk_A, pk_B)                     (nunca transmitido, descartado após derivar)
salt_par  = SHA256(salt_do_menor_id ‖ salt_do_maior_id)[:16]
PRK       = HKDF-Extract(salt_par, Z_AB)
Key_A2B   = HKDF-Expand(PRK, "A2B", 16)
Key_B2A   = HKDF-Expand(PRK, "B2A", 16)
```

O cliente com o **menor `client_id`** (comparação de bytes) é o "A". Ele envia com `Key_A2B` e recebe com `Key_B2A`; o "B" faz o inverso. As duas pontas concordam sem negociação.

### Frame E2E

```
[ nonce (12B) ][ sender_id (16B) ][ recipient_id (16B) ][ seq_no (8B) ][ ciphertext ‖ tag (16B) ]

nonce = IV_base (4B aleatório por direção) ‖ seq_no (8B big-endian)
AAD   = sender_id ‖ recipient_id ‖ seq_no
```

**Ordem de validação no receptor** (importa):

1. tamanho válido e `recipient_id` é o meu;
2. `sender_id` é um peer conhecido;
3. `nonce[4:12] == seq_no` e `IV_base` igual ao já aprendido na sessão;
4. decifra e verifica a tag GCM (falha = adulteração);
5. `seq_no > seq_recv` (senão = replay);
6. **só agora** atualiza `seq_recv`.

Atualizar o estado antes de autenticar permitiria que um atacante "queimasse" números de sequência com frames forjados e bloqueasse mensagens legítimas.

### Framing

Todo frame na rede tem a forma `[ comprimento (4B big-endian) ][ tipo (1B) ][ payload ]`. O tamanho é validado **antes** de ler ou alocar o corpo: comprimento `0` ou acima de 4165 bytes é erro de framing e a conexão é encerrada.

| Tipo | Nome | Sentido | Conteúdo |
|---|---|---|---|
| `0x01` | HELLO | C→S (claro) | `client_id(16) ‖ pk_C(32)` |
| `0x02` | HELLO_REPLY | S→C (claro, assinado) | `pk_S(32) ‖ salt(16) ‖ assinatura ‖ server.crt` |
| `0x10` | REGISTER_ACK | S→C (controle) | — |
| `0x11` | PEER_INFO | S→C (controle) | `client_id(16) ‖ pk(32) ‖ salt(16)` |
| `0x12` | PEER_LEAVE | S→C (controle) | `client_id(16)` |
| `0x13` | ERROR | S→C (controle) | `código(1) ‖ detalhe` |
| `0x14` | LIST_REQ | C→S (controle) | — |
| `0x15` | BYE | C→S (controle) | — |
| `0x20` | E2E | C→S→C (relay) | frame E2E acima |

## Requisitos

- Python 3.10 ou superior
- Biblioteca [`cryptography`](https://cryptography.io) (e `pytest`, apenas para os testes)

## Instalação

```bash
git clone <url-do-repositorio>
cd <pasta-do-projeto>

# opcional: ambiente virtual
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
.venv\Scripts\Activate.ps1         # Windows (PowerShell)

python -m pip install -r requirements.txt
```

## Como executar

**1. Gerar a chave e o certificado do servidor** (uma única vez):

```bash
python tools/gen_cert.py
```

Cria `certs/server.key` (chave privada, **nunca** vai para o git) e `certs/server.crt` (certificado público, distribuído aos clientes).

**2. Iniciar o servidor:**

```bash
python server.py --host 0.0.0.0 --port 8443
```

**3. Iniciar os clientes**, um terminal para cada. O certificado é pinado via `--cert`:

```bash
python client.py --host 127.0.0.1 --port 8443 --cert certs/server.crt --label A
python client.py --host 127.0.0.1 --port 8443 --cert certs/server.crt --label B
```

Para usar computadores diferentes, copie **somente** `certs/server.crt` para os clientes e use o IP do servidor em `--host`. O `server.key` nunca sai do servidor.

### Comandos do cliente

| Comando | O que faz |
|---|---|
| `/peers` | Lista os peers conectados (índice, id, fingerprint) |
| `/msg <peer> <texto>` | Envia mensagem E2E (peer = índice de `/peers` ou prefixo do id) |
| `/all <texto>` | Envia a mesma mensagem (cifrada separadamente) a todos |
| `/fp` | Mostra seu id e o fingerprint da sua chave pública |
| `/refresh` | Pede ao servidor a lista de peers novamente |
| `/tamper <peer> <texto>` | **Demo:** envia mensagem com 1 bit adulterado |
| `/replay` | **Demo:** reenvia o último frame enviado |
| `/help` | Mostra a ajuda |
| `/quit` | Encerra o cliente |

Para reconectar com o mesmo identificador: `python client.py --cert certs/server.crt --client-id <uuid>`.

### Opções do servidor

| Opção | Descrição |
|---|---|
| `--host`, `--port` | Endereço e porta de escuta (padrão `127.0.0.1:8443`) |
| `--key`, `--cert` | Caminhos da chave privada e do certificado |
| `--max-clients` | Limite de conexões simultâneas (padrão 100) |
| `--show-ciphertext` | **Demo:** loga o início do ciphertext para provar que é ilegível |
| `--demo-tamper` | **Demo:** relay malicioso que inverte 1 bit de cada frame |
| `--demo-replay` | **Demo:** relay malicioso que repassa cada frame duas vezes |
| `-v` | Logs detalhados |

## Testes e demonstração

```bash
python -m pytest -q      # testes automatizados (70)
python demo.py           # demonstração automática (24 verificações)
```

O `demo.py` sobe o próprio servidor e os clientes e mostra, sem precisar de vários terminais:

| Cenário | Resultado esperado |
|---|---|
| Mensagens E2E entre 2+ clientes | O destinatário decifra; um terceiro cliente não recebe nada legível |
| Adulteração (bitflip) | O destinatário rejeita por tag GCM inválida e a sessão continua funcionando |
| Replay | O destinatário rejeita por `seq_no` já usado |
| Framing inválido | O servidor fecha a conexão e segue atendendo os demais |
| Servidor impostor | O cliente recusa certificado diferente do pinado e assinatura inválida |
| Reconexão com o mesmo `client_id` | Novo handshake, novo salt, novas chaves e contadores zerados |

Para os ataques de framing contra um servidor em execução:

```bash
python tools/framing_attack.py --port 8443
```

## Decisões de projeto

O enunciado deixa alguns pontos em aberto. As decisões tomadas:

1. **`pk_S` no hash `H`** é a chave X25519 **efêmera do servidor** (32 B, nova a cada conexão). O RSA apenas assina.
2. **Canal de controle:** derivado de `ECDH(sk_C, pk_S)` com `salt_srv` e labels `"C2S"`/`"S2C"`. Nonce = direção (4 B) ‖ `seq_no` (8 B).
3. **Salt do par A↔B:** cada cliente recebe um `salt_srv` próprio, então o par usa `salt_par = SHA256(salt_menor_id ‖ salt_maior_id)[:16]`.
4. **`IV_base`:** 4 bytes aleatórios por direção, enviados no próprio campo `nonce`. O receptor o aprende na primeira mensagem **autenticada** e exige que não mude.
5. **Assinatura:** `H` (32 B) é assinado com RSA-PSS (MGF1-SHA256, salt de 32 B).
6. **Byte de tipo** após o prefixo de tamanho, para distinguir handshake, controle e E2E.
7. **`client_id`** precisa ser UUID v4. Um `client_id` duplicado enquanto o anterior estiver conectado é recusado.
8. **`PEER_INFO` repetido da mesma sessão** (mesma `pk` e mesmo `salt`) é ignorado. Recriar o peer zeraria `seq_send`, `seq_recv` e `IV_base`, desarmando o anti-replay. Uma reconexão real traz `pk` e `salt` novos e recria o peer normalmente.
9. **Limite de texto claro: 4096 bytes**, para caber em um único frame (4165 B), evitar fragmentação e limitar a memória por conexão.
10. **Limites de recursos:** `--max-clients`, timeout de handshake (10 s), timeout de corpo de frame (30 s) e desconexão de clientes que não drenam a escrita (10 s).

## Estruturas de dados

**Servidor:** `RelayServer.sessions: dict[client_id → Session]`

| Campo | Significado |
|---|---|
| `writer` | `StreamWriter` da conexão |
| `public_key` | `pk_C` (32 B) |
| `salt` | `salt_srv` (16 B) |
| `seq_recv` / `seq_send` | Contadores do canal de controle (`-1` e `0` no início) |
| chaves `C2S`/`S2C` | Apenas do canal de controle. **Nenhuma chave E2E** |

**Cliente:** `SecureClient.peers: dict[client_id → Peer]`

| Campo | Significado |
|---|---|
| `public_key` / `salt` | `pk` e `salt_srv` do peer |
| `key_send` / `key_recv` | `Key_A2B`/`Key_B2A` (ou o inverso, pela regra A/B) |
| `seq_send` / `seq_recv` | `0` e `-1` no início |
| `iv_base_send` / `iv_base_recv` | `IV_base` de cada direção |
| `Z_AB` | **Não é armazenado** (descartado após a derivação) |

## Política de logs

- **Permitido:** conexão e desconexão, `client_id`, tamanhos de mensagem, motivos de rejeição (por exemplo "tag GCM inválida" ou "replay detectado") e fingerprints de chaves públicas.
- **Proibido:** chaves privadas, `Z`, chaves derivadas, `salt`, nonces e conteúdo de mensagens.

Como defesa em profundidade, `common/log_utils.py` instala um filtro que bloqueia qualquer log com argumento `bytes`, e `tests/test_log_policy.py` confere que nenhum segredo aparece nos logs de uma sessão completa.

## Limitações conhecidas

- **Servidor malicioso na distribuição de chaves:** como o servidor entrega as chaves públicas dos clientes, ele poderia trocá-las e fazer MITM entre A e B. A mitigação é comparar os **fingerprints** por outro canal (`/fp` e `/peers`).
- **`client_id` não é autenticado** (o enunciado não prevê autenticação de clientes).
- **Não há irretratabilidade:** a chave simétrica é compartilhada pelos dois lados.
- **Metadados visíveis ao servidor:** quem fala com quem, quando e o tamanho dos frames.
- **Sem rotação de chaves** (opcional no enunciado). Reconectar gera chaves novas.
- Python não garante apagar segredos da memória; o código apenas descarta as referências.

## Estrutura do projeto

```
server.py            servidor relay (handshake, sessions, relay, controle)
client.py            SecureClient (protocolo) + CLI interativa
demo.py              demonstração automática dos testes obrigatórios
common/
  protocol.py        constantes, tipos de frame, formatos e parsers
  framing.py         prefixo de tamanho de 4 B e validações
  crypto.py          X25519, HKDF (RFC 5869), AES-128-GCM, RSA-PSS, nonce
  channel.py         canal de controle servidor↔cliente (AES-GCM + seq_no)
  certs.py           geração e carga do certificado autoassinado
  log_utils.py       política de logs e filtro anti-segredo
tools/
  gen_cert.py        gera server.key e server.crt
  framing_attack.py  envia frames inválidos ao servidor
tests/               testes de criptografia, framing, logs e integração/ataques
docs/                roteiro da apresentação
```

## Segurança do repositório

- **Nunca** faça commit do `certs/server.key`. Ele já está no `.gitignore`, junto com `*.key` e `*.pem`.
- Cada ambiente deve gerar o próprio par com `python tools/gen_cert.py`.
