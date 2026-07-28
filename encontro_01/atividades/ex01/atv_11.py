

import hashlib
import hmac
import secrets

def sha256(mensagem):
    return hashlib.sha256(mensagem).digest()

def criar_hmac(chave, mensagem):
    # TODO: produza um HMAC-SHA-256.
    pass

def verificar_hmac(chave, mensagem, etiqueta):
    # TODO: recalcule e use hmac.compare_digest.
    pass


original = b"destino=ana;valor=100"
alterada = b"destino=ana;valor=900"


# SHA-256 nao possui chave. O atacante consegue recalcular o resumo.
hash_original = sha256(original)
hash_forjado = sha256(alterada)
assert hash_forjado == sha256(alterada)


# O servidor e o remetente compartilham esta chave; o atacante nao.
chave_legitima = secrets.token_bytes(32)
chave_atacante = secrets.token_bytes(32)
etiqueta_original = criar_hmac(chave_legitima, original)
assert verificar_hmac(chave_legitima, original, etiqueta_original)


# TODO: crie uma etiqueta para a mensagem alterada com a chave do atacante
# e confirme que o servidor a rejeita.




