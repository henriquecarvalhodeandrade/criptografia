import hashlib
import hmac
import secrets


def sha256(mensagem):
    return hashlib.sha256(mensagem).digest()


def criar_hmac(chave, mensagem):
    """
    Calcula um HMAC-SHA-256 para a mensagem utilizando a chave secreta.
    Retorna apenas os bytes da etiqueta.
    """
    return hmac.new(chave, mensagem, hashlib.sha256).digest()


def verificar_hmac(chave, mensagem, etiqueta):
    """
    Recalcula o HMAC da mensagem utilizando a chave fornecida e compara
    com a etiqueta recebida de forma segura.
    """
    etiqueta_servidor = criar_hmac(chave, mensagem)
    return hmac.compare_digest(etiqueta_servidor, etiqueta)


original = b"destino=ana;valor=100"
alterada = b"destino=ana;valor=900"

# SHA-256 não possui chave. O atacante consegue recalcular
# o hash da mensagem alterada.
hash_original = sha256(original)
hash_forjado = sha256(alterada)

# A verificação passa, pois o atacante recalculou o hash.
assert hash_forjado == sha256(alterada)
print("SHA-256: a mensagem alterada acompanhada de um novo hash é aceita.")

# O servidor e o remetente compartilham esta chave.
chave_legitima = secrets.token_bytes(32)


chave_atacante = secrets.token_bytes(32)


etiqueta_original = criar_hmac(chave_legitima, original)
assert verificar_hmac(chave_legitima, original, etiqueta_original)
print("HMAC: a mensagem original foi autenticada com sucesso.")


# Tentativa de ataque
# O atacante altera a mensagem e gera uma etiqueta usando
# a própria chave.
etiqueta_atacante = criar_hmac(chave_atacante, alterada)

assert not verificar_hmac(
    chave_legitima,
    alterada,
    etiqueta_atacante
)

print("Ataque rejeitado: o HMAC criado com outra chave não é aceito.")