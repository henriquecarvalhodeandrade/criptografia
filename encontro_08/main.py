def e(x, k=3):
    return (x + k) % 16

def d(y, k=3):
    return (y - k) % 16

def _bloco(valor, nome="bloco"):
    if not isinstance(valor, int) or not 0 <= valor <= 15:
        raise ValueError(f"{nome} deve estar entre 0 e 15")

def cbc(blocos, iv):
    _bloco(iv, "IV")
    saida = []
    anterior = iv
    for m in blocos:
        _bloco(m)
        c = e(m ^ anterior)
        saida.append(c)
        anterior = c
    return saida

def dec_cbc(blocos, iv):
    _bloco(iv, "IV")
    saida = []
    anterior = iv
    for c in blocos:
        _bloco(c)
        m = d(c) ^ anterior
        saida.append(m)
        anterior = c
    return saida

def ctr(blocos, nonce, inicio=0):
    if not isinstance(nonce, int) or not 0 <= nonce <= 3:
        raise ValueError("nonce deve estar entre 0 e 3")
    if not isinstance(inicio, int) or not 0 <= inicio <= 3:
        raise ValueError("contador inicial deve estar entre 0 e 3")
    if len(blocos) > 4 - inicio:
        raise ValueError("contador de dois bits esgotado")

    saida = []
    for deslocamento, m in enumerate(blocos):
        _bloco(m)
        contador = inicio + deslocamento
        t = (nonce << 2) | contador
        fluxo = e(t)
        saida.append(m ^ fluxo)
    return saida

# Testes pedidos
c = cbc([6, 6, 6], 5)
assert c == [6, 3, 8]
assert dec_cbc(c, 5) == [6, 6, 6]

c = ctr([6, 6, 6], 2)
assert c == [13, 10, 11]       # [D, A, B]
assert ctr(c, 2) == [6, 6, 6]

assert all(d(e(x)) == x for x in range(16))

try:
    ctr([1, 2, 3, 4, 5], 2)
    raise AssertionError("deveria rejeitar cinco blocos")
except ValueError as erro:
    print("Rejeição correta:", erro)

print("CBC:", cbc([6, 6, 6], 5))
print("CBC recuperado:", dec_cbc([6, 3, 8], 5))
print("CTR:", ctr([6, 6, 6], 2))
print("CTR recuperado:", ctr([13, 10, 11], 2))
print("Inversa válida para os 16 valores")