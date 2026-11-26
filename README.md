# DCC075 - Trabalho Final

Este repositório contém o serviço vulnerável usado nos experimentos e os scripts de ataque.

## Estrutura

- `vulnerable/`: serviço de sessão em AES-CBC com falhas propositais de padding oracle e bit-flipping.
- `attacks/`: scripts que exploram as falhas do serviço vulnerável.

## Ataques

### Pré-requisitos

```bash
pip install flask pycryptodome requests
```

### Como rodar

Terminal 1, na raiz do repositório:

```bash
python vulnerable/service.py
```

Terminal 2, também na raiz:

```bash
python attacks/bitflip.py
python attacks/padding_oracle.py
```

Os scripts aceitam `--base-url`, `--usuario` e `--timeout`. Exemplo:

```bash
python attacks/padding_oracle.py --base-url http://127.0.0.1:5000 --usuario ana
```

### Resultado esperado

O `bitflip.py` deve terminar com `[SUCESSO]` e mostrar a resposta de acesso administrativo. O `padding_oracle.py` deve recuperar um texto parecido com:

```text
b'admin=0;usuario=ana;exp=9999999999'
```

O padding oracle faz milhares de requisições ao servidor e pode levar alguns segundos.

## Aviso

Use os scripts apenas no ambiente local do trabalho.
