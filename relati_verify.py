#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
relati-verify: verificador independente de evidências de consentimento Relati.

Funciona em qualquer máquina com Python 3.8+, sem depender de servidores do
Relati. A verificação de integridade e da âncora blockchain NÃO exige chave
nenhuma; a chave de decifragem só é necessária pra abrir a cópia selada
(cifrada) do pacote de evidência.

Comandos:
  hash      Recalcula o hash canônico (RFC 8785 + SHA-256) de um pacote JSON.
  verify    hash + confere a âncora na blockchain Polygon (via RPC público).
  check-tx  Confere só a âncora: o hash está gravado na transação?
  decrypt   Decifra a cópia selada (v1:iv:tag:ct, AES-256-GCM) com uma chave.
  filehash  SHA-256 de um arquivo (vídeo de consentimento, foto) pra comparar
            com o hash carimbado na evidência.

Formato dos dados (imutável por contrato):
  - Pacote de evidência: JSON canonicalizado por RFC 8785 (JCS), SHA-256 em hex.
  - Âncora: transação Polygon de self-transfer com `input` = 0x<hash>.
  - Cópia selada: "v{n}:{iv_b64}:{tag_b64}:{ct_b64}", AES-256-GCM, chave de
    32 bytes (64 hex ou base64).
"""

import argparse
import base64
import hashlib
import json
import math
import sys
import urllib.request

RPC_DEFAULT = {
    "polygon": "https://polygon-rpc.com",
    "amoy": "https://rpc-amoy.polygon.technology",
}
EXPLORER = {
    "polygon": "https://polygonscan.com/tx/",
    "amoy": "https://amoy.polygonscan.com/tx/",
}


# ---------------------------------------------------------------------------
# RFC 8785 (JSON Canonicalization Scheme) — suficiente e fiel pro schema dos
# pacotes Relati (strings, inteiros, booleanos, objetos e arrays; floats são
# cobertos pelo algoritmo de número do ECMAScript nos casos práticos).
# ---------------------------------------------------------------------------

def _jcs_number(value):
    if isinstance(value, bool):  # bool antes de int: bool é subclasse de int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN/Infinity não são permitidos em JSON canônico")
    if value == 0:
        return "0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)  # shortest round-trip, igual ao ECMAScript
    if "e" in text:
        mantissa, exp = text.split("e")
        exp_int = int(exp)
        text = f"{mantissa}e{'+' if exp_int >= 0 else '-'}{abs(exp_int)}"
    return text


def _jcs_string(value):
    return json.dumps(value, ensure_ascii=False)


def jcs_canonicalize(value):
    """Serializa `value` conforme RFC 8785."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        # Ordena por unidades de código UTF-16 (RFC 8785 §3.2.3)
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_jcs_string(k)}:{jcs_canonicalize(v)}" for k, v in items) + "}"
    raise TypeError(f"Tipo não serializável em JSON: {type(value)}")


def packet_hash(packet):
    canonical = jcs_canonicalize(packet)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), canonical


# ---------------------------------------------------------------------------
# Polygon JSON-RPC (sem dependências: urllib)
# ---------------------------------------------------------------------------

def rpc_call(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json", "User-Agent": "relati-verify"}
    )
    with urllib.request.urlopen(req, timeout=30) as res:
        payload = json.loads(res.read().decode())
    if "error" in payload:
        raise RuntimeError(f"RPC {method}: {payload['error']}")
    return payload.get("result")


def check_anchor(rpc_url, tx_hash, evidence_hash):
    tx = rpc_call(rpc_url, "eth_getTransactionByHash", [tx_hash])
    if not tx:
        return {"found": False}
    data = (tx.get("input") or "").lower()
    expected = "0x" + evidence_hash.lower().removeprefix("0x")
    result = {
        "found": True,
        "hash_matches": data == expected,
        "from": tx.get("from"),
        "to": tx.get("to"),
        "block_number": None,
        "timestamp_utc": None,
    }
    if tx.get("blockNumber"):
        result["block_number"] = int(tx["blockNumber"], 16)
        block = rpc_call(rpc_url, "eth_getBlockByNumber", [tx["blockNumber"], False])
        if block and block.get("timestamp"):
            import datetime

            ts = int(block["timestamp"], 16)
            result["timestamp_utc"] = datetime.datetime.fromtimestamp(
                ts, datetime.timezone.utc
            ).isoformat()
    return result


# ---------------------------------------------------------------------------
# Decifragem da cópia selada (opcional: exige `pip install cryptography`)
# ---------------------------------------------------------------------------

def parse_key(text):
    text = text.strip()
    if len(text) == 64:
        try:
            key = bytes.fromhex(text)
            if len(key) == 32:
                return key
        except ValueError:
            pass
    key = base64.b64decode(text)
    if len(key) != 32:
        raise ValueError("A chave precisa ter 32 bytes (64 hex ou base64).")
    return key


def decrypt_blob(blob, key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        sys.exit(
            "O comando decrypt precisa do pacote 'cryptography'.\n"
            "Instale com:  pip install cryptography"
        )
    parts = blob.strip().split(":")
    if len(parts) != 4 or not parts[0].startswith("v"):
        raise ValueError("Formato esperado: v{n}:iv:tag:ciphertext (base64)")
    iv = base64.b64decode(parts[1])
    tag = base64.b64decode(parts[2])
    ct = base64.b64decode(parts[3])
    return AESGCM(key).decrypt(iv, ct + tag, None).decode("utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_packet(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


NETWORK_BY_LABEL = {"polygon-mainnet": "polygon", "polygon-amoy": "amoy"}


def _is_bundle(doc):
    return isinstance(doc, dict) and str(doc.get("formato", "")).startswith("relati-prova")


def _verify_bundle(doc, rpc_override=None):
    """Pacote de prova baixado do painel: verifica cada evidência (hash local
    contra o registrado e, quando ancorada, contra a transação na Polygon)."""
    failures = 0
    evidencias = doc.get("evidencias", [])
    if not evidencias:
        sys.exit("pacote de prova sem evidências: nada a verificar.")
    print(f"pacote de prova relati: {len(evidencias)} evidência(s)\n")
    for i, ev in enumerate(evidencias, 1):
        prova = ev.get("prova", {})
        digest, _ = packet_hash(ev.get("pacote"))
        expected = (prova.get("evidence_hash") or "").lower()
        hash_ok = digest == expected
        print(f"[{i}] evidência {ev.get('evidence_id', '?')}")
        print(f"    hash canônico:  {digest}")
        print(f"    hash registrado: {expected or '(ausente)'}  " + ("✓" if hash_ok else "✗ DIVERGIU"))
        if not hash_ok:
            failures += 1
            continue
        tx = prova.get("tx_hash")
        if not tx:
            print(f"    âncora: {prova.get('anchoring_status') or 'sem transação'} (nada a conferir on-chain)")
            continue
        network = NETWORK_BY_LABEL.get(prova.get("anchor_network") or "", "polygon")
        result = check_anchor(rpc_override or RPC_DEFAULT[network], tx, digest)
        if not result["found"]:
            print(f"    âncora: transação NÃO encontrada ✗ ({EXPLORER[network]}{tx})")
            failures += 1
            continue
        ok = result["hash_matches"]
        print(f"    âncora: {EXPLORER[network]}{tx}")
        print(f"    hash na blockchain confere: " + ("SIM ✓" if ok else "NÃO ✗"))
        if result["timestamp_utc"]:
            print(f"    ancorado em (UTC): {result['timestamp_utc']} (bloco {result['block_number']})")
        if not ok:
            failures += 1
    print()
    if failures:
        print(f"VEREDITO: {failures} evidência(s) FALHARAM na verificação. ✗")
        sys.exit(2)
    print("VEREDITO: todas as evidências conferem com o registrado e ancorado. ✓")


def cmd_hash(args):
    packet = _load_packet(args.packet)
    digest, canonical = packet_hash(packet)
    if args.show_canonical:
        print(canonical)
    print(f"hash canônico (SHA-256): {digest}")
    if args.expected:
        ok = digest == args.expected.lower().removeprefix("0x")
        print("confere com o esperado: " + ("SIM ✓" if ok else "NÃO ✗"))
        sys.exit(0 if ok else 2)


def _resolve_rpc(args):
    return args.rpc or RPC_DEFAULT[args.network]


def _print_anchor(result, network, tx):
    if not result["found"]:
        print("transação NÃO encontrada na rede ✗")
        sys.exit(2)
    print(f"transação: {EXPLORER[network]}{tx}")
    print(f"hash gravado na blockchain confere: " + ("SIM ✓" if result["hash_matches"] else "NÃO ✗"))
    if result["timestamp_utc"]:
        print(f"ancorado em (UTC): {result['timestamp_utc']}  (bloco {result['block_number']})")
    if not result["hash_matches"]:
        sys.exit(2)


def cmd_verify(args):
    packet = _load_packet(args.packet)
    if _is_bundle(packet):
        _verify_bundle(packet, rpc_override=args.rpc)
        return
    if not args.tx:
        sys.exit("Para um pacote avulso, informe --tx (o pacote de prova do painel dispensa).")
    digest, _ = packet_hash(packet)
    print(f"hash canônico (SHA-256): {digest}")
    result = check_anchor(_resolve_rpc(args), args.tx, digest)
    _print_anchor(result, args.network, args.tx)
    print("\nVEREDITO: o pacote de evidência é exatamente o que foi ancorado. ✓")


def cmd_check_tx(args):
    result = check_anchor(_resolve_rpc(args), args.tx, args.hash)
    _print_anchor(result, args.network, args.tx)


def cmd_decrypt(args):
    import os

    blob = args.blob
    if os.path.exists(blob):
        with open(blob, "r", encoding="utf-8") as f:
            blob = f.read()
    key_text = args.key
    if os.path.exists(key_text):
        with open(key_text, "r", encoding="utf-8") as f:
            key_text = f.read()
    plaintext = decrypt_blob(blob, parse_key(key_text))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(plaintext)
        print(f"pacote decifrado salvo em {args.output}")
        print("verifique com:  python3 relati_verify.py verify " + args.output + " --tx <tx_hash>")
    else:
        print(plaintext)


def cmd_filehash(args):
    h = hashlib.sha256()
    with open(args.file, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    print(f"SHA-256: {h.hexdigest()}")


def main():
    parser = argparse.ArgumentParser(
        prog="relati_verify.py",
        description="Verificador independente de evidências de consentimento Relati.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_chain_args(p):
        p.add_argument("--network", choices=["polygon", "amoy"], default="polygon")
        p.add_argument("--rpc", help="URL de um RPC próprio (opcional)")

    p = sub.add_parser("hash", help="hash canônico de um pacote JSON")
    p.add_argument("packet")
    p.add_argument("--expected", help="hash esperado pra comparar")
    p.add_argument("--show-canonical", action="store_true")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("verify", help="hash + âncora na Polygon")
    p.add_argument("packet", help="pacote de prova do painel OU pacote de evidência avulso")
    p.add_argument("--tx", help="transação de ancoragem (só pra pacote avulso)")
    add_chain_args(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("check-tx", help="confere só a âncora on-chain")
    p.add_argument("--tx", required=True)
    p.add_argument("--hash", required=True, help="evidence_hash esperado")
    add_chain_args(p)
    p.set_defaults(func=cmd_check_tx)

    p = sub.add_parser("decrypt", help="decifra a cópia selada com a chave")
    p.add_argument("blob", help="string v1:iv:tag:ct ou arquivo que a contenha")
    p.add_argument("--key", required=True, help="chave (64 hex ou base64) ou arquivo com ela")
    p.add_argument("-o", "--output", help="salvar o JSON decifrado em arquivo")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("filehash", help="SHA-256 de um arquivo (vídeo/foto)")
    p.add_argument("file")
    p.set_defaults(func=cmd_filehash)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
