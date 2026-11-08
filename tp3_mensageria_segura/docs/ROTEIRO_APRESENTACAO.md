# Roteiro da apresentação (dupla) e perguntas prováveis

Tempo sugerido: 15–20 min. Sigam o checklist do enunciado: cada aluno fala e apresenta trechos
**diferentes** do código.

## Divisão

| | Integrante 1 | Integrante 2 |
|---|---|---|
| Fala | Abertura, protocolo, **handshake**, **derivação de chaves** | **AES-GCM**, **roteamento/servidor**, demonstração, encerramento |
| Código | `client._handshake`, `server._handshake`, `crypto.handshake_hash`/`rsa_pss_*`, `client.derive_e2e_keys`, `crypto.hkdf_*` | `client._build_e2e`, `client._on_e2e`, `server._relay`, `Session`/`sessions`, `common/log_utils.py` |

## Sequência

1. **(Ambos, 1 min)** Apresentação dos integrantes e objetivo: servidor como relay, E2E.
2. **(Int. 1, 4 min)** Diagrama do README §3.2. Por que DH puro não basta (slide "Problemas nos dois
   métodos": sem autenticação → MITM) e como o RSA-PSS sobre `H` + certificado **pinado** resolve.
   Mostrar `crypto.handshake_hash` e a verificação em `client._handshake` (verifica com o cert
   *pinado*, não com o recebido).
3. **(Int. 1, 3 min)** Derivação: `Z_AB → HKDF-Extract(salt_par) → A2B/B2A` (`client.derive_e2e_keys`).
   Regra "menor client_id é A". Por que HKDF e não PBKDF2/bcrypt/Argon2 (slides de KDF): esses são
   para senhas de baixa entropia; o segredo do ECDH já tem alta entropia.
4. **(Int. 2, 3 min)** Mensagem E2E: formato do frame, nonce `IV_base‖seq_no`, AAD, ordem de
   validação na recepção (tag antes de `seq_recv`). Mostrar `_build_e2e` e `_on_e2e`.
5. **(Int. 2, 2 min)** Servidor: tabela `sessions`, `seq_send`/`seq_recv` do canal de controle,
   `_relay` (só lê `sender_id`/`recipient_id`), política de logs.
6. **(Int. 2 conduz, Int. 1 digita, 5 min)** Demonstração (abaixo).
7. **(Int. 1, 1 min)** Encerramento: tabela de garantias do README e limitações (§7).

## Demonstração ao vivo

Preparação (antes da aula): `python tools/gen_cert.py` e `pip install -r requirements.txt`.

```text
T1  python server.py --show-ciphertext
T2  python client.py --cert certs/server.crt --label A
T3  python client.py --cert certs/server.crt --label B
T4  python client.py --cert certs/server.crt --label C
```

1. **E2E:** em A: `/peers` e `/msg 1 olá B` (use o índice correspondente ao B). B mostra a mensagem;
   C não recebe nada; T1 mostra só ciphertext.
2. **Fingerprints:** `/fp` em cada terminal e `/peers` nos outros; são os mesmos valores
   (é assim que se detecta um servidor que trocou chaves).
3. **Bitflip:** em A: `/tamper <peer> teste`. B mostra "tag GCM inválida". Em seguida mande uma
   mensagem normal para provar que a sessão continua funcionando.
4. **Replay:** em A: `/msg <peer> pague 10` e depois `/replay`. B rejeita: "replay detectado".
5. **Framing inválido:** em outro terminal: `python tools/framing_attack.py`. Todos "OK"; o servidor
   continua atendendo (mande outra mensagem).
6. **Relay malicioso (opcional):** reiniciar o servidor com `--demo-tamper` e depois `--demo-replay`.
7. **Plano B** se algo falhar na rede da sala: `python demo.py` roda tudo em uma máquina só.

## Perguntas prováveis

**Se a chave RSA vazar no futuro, o que acontece?** As sessões passadas continuam seguras: as chaves
vêm de X25519 efêmero, que nunca é armazenado, e o RSA só assina. O atacante poderia se passar
pelo servidor em conexões *futuras*, não decifrar o tráfego antigo.

**Por que RSA se já existe ECDHE?** ECDHE sozinho não autentica e permite MITM. O RSA autentica o
servidor.

**Por que a assinatura cobre `pk_C`, `client_id` e `salt`?** Para amarrar a resposta àquela conexão:
uma resposta gravada antes não serve em outra conexão (anti-replay do handshake).

**Por que o nonce não pode repetir no GCM?** Repetir (chave, nonce) vaza o XOR dos textos claros e
permite forjar tags. Aqui cada direção tem chave própria e `seq_no` nunca repete.

**Por que atualizar `seq_recv` só depois da tag?** Senão um atacante injeta frames forjados com
`seq_no` alto e faz o receptor rejeitar as mensagens legítimas seguintes.

**O servidor pode fazer MITM entre A e B?** Sim, porque ele distribui as chaves públicas. Mitigação:
comparar fingerprints por outro canal. É uma limitação da arquitetura do enunciado.

**Por que 4096 bytes?** Cabe em um frame de 4165 B (sem fragmentação), limita memória por conexão e
é suficiente para mensagens de chat.

**E o `IV_base`, se é aleatório, como o receptor sabe?** Vai no campo `nonce` do frame. O receptor
aprende na 1ª mensagem autenticada e exige que não mude; também confere `nonce[4:12] == seq_no`.

**O servidor guarda alguma chave E2E?** Não. A tabela `sessions` só tem `writer`, `pk_C`, `salt` e
contadores/chaves do **canal de controle**.

**Quem garante irretratabilidade?** Ninguém: a chave simétrica é compartilhada, então qualquer um
dos dois poderia ter gerado a mensagem. Só assinaturas digitais por mensagem dariam isso.

**Como o servidor reage a framing inválido?** Valida o tamanho antes de ler: `0` ou `> 4165` fecha a
conexão (com `ERROR` de controle, se a sessão já existir) e segue atendendo os demais.

## E-mail curto ao professor (opcional, confirma as decisões)

> Professor, no TP3 estamos interpretando `pk_S` do hash `H` como a chave X25519 **efêmera** do
> servidor (o RSA só assina), e, para que A e B usem o mesmo salt no HKDF, o servidor entrega o
> `salt_srv` de cada peer e ambos calculam `salt_par = SHA256(salt_menor_id ‖ salt_maior_id)[:16]`.
> Está de acordo?
