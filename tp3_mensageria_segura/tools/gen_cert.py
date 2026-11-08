#!/usr/bin/env python3
"""Gera o par RSA do servidor e o certificado autoassinado.

    python tools/gen_cert.py                 # certs/server.key + certs/server.crt
    python tools/gen_cert.py --bits 3072

- server.key: chave PRIVADA. Fica só no servidor (permissão 0600). NUNCA vai para o git.
- server.crt: certificado PÚBLICO. É copiado para os clientes, que o "pinam".
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import certs  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="certs", help="diretório de saída")
    p.add_argument("--cn", default="tp3-relay", help="Common Name do certificado")
    p.add_argument("--bits", type=int, default=2048, help="tamanho da chave RSA (>= 2048)")
    p.add_argument("--days", type=int, default=3650)
    p.add_argument("--force", action="store_true", help="sobrescrever arquivos existentes")
    args = p.parse_args()

    key_path = os.path.join(args.out, "server.key")
    crt_path = os.path.join(args.out, "server.crt")
    if not args.force and (os.path.exists(key_path) or os.path.exists(crt_path)):
        print(f"[ERRO] {key_path} ou {crt_path} já existe (use --force para sobrescrever)")
        return 1
    os.makedirs(args.out, exist_ok=True)
    key, cert = certs.generate_self_signed(args.cn, args.bits, args.days)
    certs.save_key(key_path, key)
    certs.save_cert(crt_path, cert)
    print(f"Chave privada : {key_path}  (mantenha em segredo)")
    print(f"Certificado   : {crt_path}  (distribua aos clientes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
