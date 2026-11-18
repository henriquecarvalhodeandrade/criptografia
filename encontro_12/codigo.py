import secrets, unittest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
 
P, Q, G = 23, 11, 2
 
def validar(y):
    return type(y) is int and 2 <= y <= P - 2 and pow(y, Q, P) == 1
 
def _privada_ok(x):
    if type(x) is not int or not (1 <= x <= 10):
        raise ValueError(f"privada inválida: {x!r}")
 
def acordo_auditado(a, b):
    _privada_ok(a); _privada_ok(b)
    A, B = pow(G, a, P), pow(G, b, P)
    if not (validar(A) and validar(B)):
        raise ValueError("pública fora do subgrupo")
    return (A, B, pow(B, a, P), pow(A, b, P))   # (A, B, s_alice, s_bob)
 
assert acordo_auditado(2, 5) == (4, 9, 12, 12)
assert validar(4) is True
assert validar(5) is False
assert validar(True) is False
 
# tabela independente de potências de 2 (sem usar pow), para conferência manual
POT = [1]
for _ in range(10):
    POT.append(POT[-1] * G % P)          # 2^0 .. 2^10 mod 23
 
# ---------- Parte B: X25519 + HKDF + AES-GCM ----------
def pub_bytes(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
 
def campo(b):                              # comprimento de 4 bytes + conteúdo
    return len(b).to_bytes(4, "big") + b
 
def contexto(versao, nome_a, nome_b, pub_a, pub_b):
    return b"".join(campo(x) for x in (versao, nome_a, nome_b, pub_a, pub_b))
 
def derivar(segredo, sal, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sal, info=info).derive(segredo)
 
class Teste(unittest.TestCase):
    def test_1_contratos(self):
        self.assertEqual(acordo_auditado(2, 5), (4, 9, 12, 12))
        for x in (0, 11, -1, True):
            with self.assertRaises(ValueError):
                acordo_auditado(x, 3)
 
    def test_2_100_pares(self):
        for a in range(1, 11):
            for b in range(1, 11):
                A, B, sa, sb = acordo_auditado(a, b)
                self.assertEqual(sa, sb)
                self.assertEqual((A, B), (POT[a % 11], POT[b % 11]))      # públicas pela tabela
                self.assertEqual(sa, POT[(a * b) % 11])                   # 2^(ab) pela ordem 11
        # conferência manual de pares: (4,3)->(16,8,2); (10,10)->(12,12,2); (1,1)->(2,2,2)
        self.assertEqual(acordo_auditado(4, 3), (16, 8, 2, 2))
        self.assertEqual(acordo_auditado(10, 10), (12, 12, 2, 2))
        self.assertEqual(acordo_auditado(1, 1), (2, 2, 2, 2))
 
    def test_3_validacao(self):
        esperado = {-1: False, 0: False, 1: False, 4: True, 5: False, 22: False, 23: False, True: False, 2.0: False}
        for y, ok in esperado.items():
            with self.subTest(y=y):
                self.assertIs(validar(y), ok)
 
    def test_4_intermediario(self):
        a, b, u, v = 2, 5, 1, 2
        A, B, _, _ = acordo_auditado(a, b)
        U, V = pow(G, u, P), pow(G, v, P)
        self.assertEqual((U, V), (2, 4))
        self.assertTrue(validar(U) and validar(V))              # as falsas passam na validação
        self.assertEqual((pow(U, a, P), pow(A, u, P)), (4, 4))  # Alice <-> Mallory
        self.assertEqual((pow(V, b, P), pow(B, v, P)), (12, 12))  # Bob <-> Mallory
        self.assertNotEqual(4, 12)
 
    def test_5_biblioteca(self):
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        A, B = pub_bytes(a), pub_bytes(b)
        sa = a.exchange(X25519PublicKey.from_public_bytes(B))
        sb = b.exchange(X25519PublicKey.from_public_bytes(A))
        self.assertEqual(sa, sb); self.assertEqual(len(sa), 32)
        sal, ctx = secrets.token_bytes(16), contexto(b"v1", b"Alice", b"Bob", A, B)
        k_ab = derivar(sa, sal, ctx + b"|A->B")
        k_ba = derivar(sa, sal, ctx + b"|B->A")
        self.assertEqual(k_ab, derivar(sb, sal, ctx + b"|A->B"))
        self.assertNotEqual(k_ab, k_ba)                              # rótulos distintos
        nonce, aad = secrets.token_bytes(12), b"v1"
        reg = AESGCM(k_ab).encrypt(nonce, b"nota=8.5", aad)
        self.assertEqual(len(reg), 24)
        self.assertEqual(AESGCM(k_ab).decrypt(nonce, reg, aad), b"nota=8.5")
        # previsão: contexto diferente no receptor -> chave diferente -> InvalidTag
        k_errada = derivar(sb, sal, contexto(b"v1", b"Alice", b"Bob", A, B) + b"|outro")
        with self.assertRaises(InvalidTag):
            AESGCM(k_errada).decrypt(nonce, reg, aad)
        with self.assertRaises(InvalidTag):
            AESGCM(k_ab).decrypt(nonce, bytes([reg[0] ^ 1]) + reg[1:], aad)
        with self.assertRaises(InvalidTag):
            AESGCM(k_ab).decrypt(nonce, reg, b"v2")
        # repetição: o MESMO registro válido é aceito de novo (a etiqueta não vê o estado)
        self.assertEqual(AESGCM(k_ab).decrypt(nonce, reg, aad), b"nota=8.5")
        self.assertEqual(AESGCM(k_ab).decrypt(nonce, reg, aad), b"nota=8.5")
        # pública composta de zeros é rejeitada
        with self.assertRaises(ValueError):
            a.exchange(X25519PublicKey.from_public_bytes(b"\x00" * 32))
 
if __name__ == "__main__":
    unittest.main(verbosity=2)

