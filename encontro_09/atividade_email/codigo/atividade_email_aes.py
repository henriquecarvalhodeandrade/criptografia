"""Gera uma chave AES e um arquivo contendo uma mensagem criptografada.

Dependência:
    python -m pip install cryptography

Execução:
    python gerar_pacote_aes.py
"""

import base64
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PASTA_SAIDA = Path("arquivos_para_enviar")
ARQUIVO_CHAVE = PASTA_SAIDA / "chave_aes.txt"
ARQUIVO_MENSAGEM = PASTA_SAIDA / "mensagem_criptografada.json"


def para_base64(dados: bytes) -> str:
    """Converte bytes em texto Base64 para facilitar o envio."""
    return base64.b64encode(dados).decode("ascii")


def main() -> None:
    mensagem = input("Digite a mensagem que será criptografada: ").strip()

    if not mensagem:
        raise ValueError("A mensagem não pode estar vazia.")

    
    chave = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(chave)
    nonce = secrets.token_bytes(12)

    
    mensagem_criptografada = aes.encrypt(
        nonce,
        mensagem.encode("utf-8"),
        None,
    )

    pacote = {
        "algoritmo": "AES-256-GCM",
        "nonce_base64": para_base64(nonce),
        "mensagem_criptografada_base64": para_base64(mensagem_criptografada),
    }

    PASTA_SAIDA.mkdir(parents=True, exist_ok=True)

    ARQUIVO_CHAVE.write_text(para_base64(chave), encoding="utf-8")
    ARQUIVO_MENSAGEM.write_text(
        json.dumps(pacote, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\nArquivos gerados com sucesso:")
    print(f"- {ARQUIVO_MENSAGEM}")
    print(f"- {ARQUIVO_CHAVE}")
    print("\nEnvie os dois arquivos aos participantes da atividade.")
    print("A chave correta permitirá recuperar a mensagem.")
    print("Uma chave AES diferente provocará falha de autenticação.")


if __name__ == "__main__":
    main()
