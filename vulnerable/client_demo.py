"""
Demonstra o servico funcionando normalmente, sem ataque nenhum.
Rode service.py em outro terminal antes.

    python vulnerable/client_demo.py
"""
import requests

BASE = "http://127.0.0.1:5000"

r = requests.post(f"{BASE}/login", json={"usuario": "ana"})
token_hex = r.json()["token"]
print("Token recebido:", token_hex)

r = requests.post(f"{BASE}/profile", json={"token": token_hex})
print("Resposta do /profile:", r.json())
