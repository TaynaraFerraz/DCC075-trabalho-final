"""
Servico VULNERAVEL de sessao em AES-CBC (sem autenticacao de integridade).

Endpoints:
    POST /login    -> cria um token de sessao cifrado para um usuario
    POST /profile  -> decifra o token e decide a resposta com base no conteudo
    GET  /stats    -> contador de chamadas ao /profile (para medir os ataques)

Duas falhas propositais:

1) PADDING ORACLE: /profile retorna uma mensagem de erro DISTINTA quando o
   padding PKCS#7 esta incorreto. Isso permite, sem conhecer a chave,
   recuperar o conteudo cifrado byte a byte (ataque classico de Vaudenay).

2) BIT-FLIPPING: o campo "admin=0/1" fica logo no INICIO do plaintext
   (primeiro bloco de 16 bytes). Como o primeiro bloco em CBC e
   D(C1) XOR IV, alterar 1 byte do IV altera exatamente 1 byte do
   texto decifrado correspondente, sem corromper mais nada.

Rodar:
    python service.py
Porta: 5000
"""

import os
import logging
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

SERVER_KEY = os.urandom(16)  # AES-128, gerada ao subir o processo
BLOCK_SIZE = 16

request_counter = {"profile_calls": 0}


def cifrar_cbc(plaintext: bytes) -> bytes:
    """Cifra em AES-CBC. Retorna IV || ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(SERVER_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return iv + ct


def decifrar_cbc(token: bytes) -> bytes:
    """Decifra IV || ciphertext. Lanca ValueError se o padding for invalido."""
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        raise ValueError("tamanho de token invalido")
    iv, ct = token[:BLOCK_SIZE], token[BLOCK_SIZE:]
    cipher = AES.new(SERVER_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), BLOCK_SIZE)  # <- levanta ValueError no padding ruim


@app.post("/login")
def login():
    """Recebe {"usuario": "ana"} e devolve um token de sessao cifrado (hex)."""
    data = request.get_json(force=True)
    usuario = data.get("usuario", "visitante")

    # IMPORTANTE: "admin=0" fica logo no inicio do plaintext, de proposito,
    # para cair sempre no primeiro bloco de 16 bytes, qualquer que seja o
    # tamanho do nome do usuario. Isso deixa o bit-flipping via IV limpo.
    plaintext = f"admin=0;usuario={usuario};exp=9999999999".encode()

    token = cifrar_cbc(plaintext)
    logging.info(f"[LOGIN] usuario={usuario} token={token.hex()[:32]}...")
    return jsonify(token=token.hex())


@app.post("/profile")
def profile():
    """Recebe {"token": "<hex>"}. Esta e a funcao ORACLE explorada pelos ataques."""
    request_counter["profile_calls"] += 1

    hex_token = request.get_json(force=True).get("token", "")
    try:
        token = bytes.fromhex(hex_token)
    except ValueError:
        return jsonify(error="token nao e hexadecimal valido"), 400

    try:
        plaintext = decifrar_cbc(token)
    except ValueError as e:
        # --- FALHA 1: PADDING ORACLE ---
        # Mensagem de erro distinta e observavel para padding incorreto.
        return jsonify(error="padding invalido", detail=str(e)), 400

    texto = plaintext.decode(errors="replace")

    # --- FALHA 2: BIT-FLIPPING ---
    # Confia no campo admin= sem nenhuma verificacao de integridade.
    if b"admin=1" in plaintext:
        resposta = "ACESSO ADMIN CONCEDIDO - bem-vindo, superusuario"
    else:
        resposta = "acesso usuario comum"

    return jsonify(mensagem=resposta, sessao=texto)


@app.get("/stats")
def stats():
    return jsonify(request_counter)


@app.post("/reset_stats")
def reset_stats():
    request_counter["profile_calls"] = 0
    return jsonify(request_counter)


if __name__ == "__main__":
    print(f"[+] Chave do servidor (nao deveria ser visivel em producao): {SERVER_KEY.hex()}")
    print("[+] Servico vulneravel em: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)