"""Implementação de xtime e gf_mul em Python 3, sem pacotes externos:"""

def xtime(valor):
    deslocado = (valor << 1) & 0xFF
    if valor & 0x80:
        deslocado ^= 0x1B
    return deslocado


def gf_mul(a, b):
    resultado = 0
    for _ in range(8):
        if b & 1:
            resultado ^= a
        a = xtime(a)
        b >>= 1
    return resultado


assert xtime(0x57) == 0xAE
assert gf_mul(0x57, 0x13) == 0xFE

for valor in range(0x100):
    assert gf_mul(valor, 0x00) == 0x00
    assert gf_mul(valor, 0x01) == valor
    assert gf_mul(valor, 0x02) == xtime(valor)

produtos = [
    gf_mul(0xD4, 0x02),
    gf_mul(0xBF, 0x03),
    gf_mul(0x5D, 0x01),
    gf_mul(0x30, 0x01),
]
primeira_saida = produtos[0] ^ produtos[1] ^ produtos[2] ^ produtos[3]
assert primeira_saida == 0x04

print(f"xtime(57) = {xtime(0x57):02X}")
print(f"57 * 13 = {gf_mul(0x57, 0x13):02X}")
print("Testes de 00 a FF: OK")
print("Produtos:", " ".join(f"{p:02X}" for p in produtos))
print(f"Primeira saída de MixColumns = {primeira_saida:02X}")


"""
Saída esperada;

xtime(57) = AE
57 * 13 = FE
Testes de 00 a FF: OK
Produtos: B3 DA 5D 30
Primeira saída de MixColumns = 04

Na primeira saída de MixColumns para [D4, BF, 5D, 30], os produtos são 02·D4 = B3, 03·BF = DA, 01·5D = 5D e 01·30 = 30. O XOR acumulado é B3 ⊕ DA = 69, 69 ⊕ 5D = 34 e 34 ⊕ 30 = 04.


"""