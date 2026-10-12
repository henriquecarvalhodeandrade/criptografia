"""Descriptografa o pacote criado por gerar_pacote_aes.py.

Dependência:
    python -m pip install cryptography

Coloque este script junto dos arquivos abaixo ou na pasta imediatamente
acima de "arquivos_para_enviar":
    - chave_aes.txt
    - mensagem_criptografada.json
"""

import base64
import binascii
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NOME_CHAVE = "chave_aes.txt"
NOME_PACOTE = "mensagem_criptografada.json"


def localizar_arquivos() -> tuple[Path, Path]:
    """Procura os arquivos na pasta atual e em arquivos_para_enviar."""
    pasta_atual = Path.cwd()
    pasta_script = Path(__file__).resolve().parent

    pastas = [
        pasta_atual,
        pasta_atual / "arquivos_para_enviar",
        pasta_script,
        pasta_script / "arquivos_para_enviar",
    ]

    for pasta in pastas:
        arquivo_chave = pasta / NOME_CHAVE
        arquivo_pacote = pasta / NOME_PACOTE

        if arquivo_chave.is_file() and arquivo_pacote.is_file():
            return arquivo_chave, arquivo_pacote

    raise FileNotFoundError(
        "Não encontrei chave_aes.txt e mensagem_criptografada.json "
        "na mesma pasta."
    )


def ler_base64(valor: str) -> bytes:
    """Converte Base64 em bytes e rejeita conteúdo inválido."""
    return base64.b64decode(valor.strip(), validate=True)


def main() -> None:
    try:
        arquivo_chave, arquivo_pacote = localizar_arquivos()

        chave = ler_base64(arquivo_chave.read_text(encoding="utf-8"))
        pacote = json.loads(arquivo_pacote.read_text(encoding="utf-8"))

        if pacote.get("algoritmo") != "AES-256-GCM":
            raise ValueError("O algoritmo informado no pacote não é AES-256-GCM.")

        nonce = ler_base64(pacote["nonce_base64"])
        mensagem_criptografada = ler_base64(
            pacote["mensagem_criptografada_base64"]
        )

        aes = AESGCM(chave)
        mensagem = aes.decrypt(nonce, mensagem_criptografada, None)

        print("Mensagem descriptografada com sucesso:")
        print(mensagem.decode("utf-8"))

    except InvalidTag:
        print("Erro de autenticação (InvalidTag).")
        print("A chave está incorreta ou o arquivo criptografado foi alterado.")

    except FileNotFoundError as erro:
        print(f"Erro: {erro}")

    except (json.JSONDecodeError, KeyError, binascii.Error, UnicodeDecodeError, ValueError) as erro:
        print(f"Erro ao ler os arquivos: {erro}")


if __name__ == "__main__":
    main()
