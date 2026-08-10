import secrets

def euclides_estendido(a, b):
    if b == 0:
        return a, 1, 0
    mdc, x1, y1 = euclides_estendido(b, a % b)
    return mdc, y1, x1 - (a // b) * y1

def inverso_modular(a, n):
    mdc, x, _ = euclides_estendido(a, n)
    if mdc != 1:
        raise ValueError(f"O inverso de {a} mod {n} nao existe pois MDC({a}, {n}) = {mdc} != 1.")
    return x % n

def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("Tamanhos diferentes.")
    return bytes(x ^ y for x, y in zip(a, b))


assert inverso_modular(7, 26) == 15
assert xor_bytes(bytes.fromhex("0f"), bytes.fromhex("f0")).hex() == "ff"

nonce = secrets.token_bytes(12)
assert len(nonce) == 12


conjunto_nonces = set()
colisao = False
for _ in range(1000):
    n = secrets.token_bytes(12)
    if n in conjunto_nonces:
        colisao = True
        break
    conjunto_nonces.add(n)

print(f"Inverso 7 mod 26: {inverso_modular(7, 26)}")
print(f"XOR 0f x f0: {xor_bytes(bytes.fromhex('0f'), bytes.fromhex('f0')).hex()}")
print(f"Teste em 1000 nonces: {colisao}")