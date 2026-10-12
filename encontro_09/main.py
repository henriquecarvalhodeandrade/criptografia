from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def alterar(dados, indice):
    copia = bytearray(dados)
    copia[indice] ^= 1
    return bytes(copia)


def esperar_invalid_tag(nome, aes_obj, nonce_teste, pacote_teste, aad_teste):
    try:
        aes_obj.decrypt(nonce_teste, pacote_teste, aad_teste)
    except InvalidTag:
        print(f"{nome}: InvalidTag")
    else:
        raise AssertionError(f"{nome}: alteração aceita indevidamente")


chave = AESGCM.generate_key(bit_length=128)
aes = AESGCM(chave)
nonce = (7).to_bytes(4, "big") + (9).to_bytes(8, "big")
versao = 1
usuario = 17
sequencia = 9
aad = bytes([versao]) + usuario.to_bytes(2, "big") + sequencia.to_bytes(4, "big")
mensagem = b"nota=8.5"

# Uma única cifração. A biblioteca devolve C seguido da etiqueta T.
pacote = aes.encrypt(nonce, mensagem, aad)
recuperada = aes.decrypt(nonce, pacote, aad)
assert len(pacote) == 24
assert recuperada == mensagem

c_tam = len(mensagem)
t_tam = len(pacote) - c_tam
print(f"Tamanhos: M={len(mensagem)}, AAD={len(aad)}, N={len(nonce)}, C={c_tam}, T={t_tam}, pacote={len(pacote)}")
print("Mensagem original:", recuperada.decode())

# Cada teste parte de uma cópia nova do registro original.
esperar_invalid_tag("C alterado", aes, nonce, alterar(pacote, 0), aad)
esperar_invalid_tag("T alterada", aes, nonce, alterar(pacote, -1), aad)
esperar_invalid_tag("AAD alterado", aes, nonce, pacote, alterar(aad, -1))
esperar_invalid_tag("Nonce alterado", aes, alterar(nonce, -1), pacote, aad)

outra_chave = AESGCM.generate_key(bit_length=128)
esperar_invalid_tag("Chave diferente", AESGCM(outra_chave), nonce, pacote, aad)

# Repetir Open é criptograficamente válido; replay é política da aplicação.
assert aes.decrypt(nonce, pacote, aad) == mensagem
assert aes.decrypt(nonce, pacote, aad) == mensagem
print("Duas aberturas intactas: válidas para AESGCM")


aceitas = set()


def receber(nonce_recebido, pacote_recebido, aad_recebido, usuario_esperado):
    # Nenhum estado é alterado se a autenticação falhar.
    texto = aes.decrypt(nonce_recebido, pacote_recebido, aad_recebido)

    if len(aad_recebido) != 7:
        raise ValueError("AAD com tamanho inválido")
    usuario_autenticado = int.from_bytes(aad_recebido[1:3], "big")
    sequencia_autenticada = int.from_bytes(aad_recebido[3:7], "big")

    if usuario_autenticado != usuario_esperado:
        raise ValueError("contexto de usuário incorreto")

    identificador = (usuario_autenticado, sequencia_autenticada)
    if identificador in aceitas:
        raise ValueError("registro repetido")

    # Em produção, a consulta, a inclusão e a ação devem ser atômicas e persistentes.
    aceitas.add(identificador)
    return texto


assert receber(nonce, pacote, aad, 17) == mensagem
print("Primeira aceitação: permitida")

try:
    receber(nonce, pacote, aad, 17)
except ValueError as erro:
    print("Segunda aceitação:", erro)

try:
    receber(nonce, pacote, aad, 18)
except ValueError as erro:
    print("Contexto errado:", erro)

estado_antes = set(aceitas)
try:
    receber(nonce, alterar(pacote, 0), aad, 17)
except InvalidTag:
    print("Falha de etiqueta não alterou o estado:", aceitas == estado_antes)