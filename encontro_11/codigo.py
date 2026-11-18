import unittest
from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
 
# ---------- Parte 1: RSA bruto didático ----------
def preparar(p, q, e):
    # Precondição didática: p e q são primos distintos fornecidos.
    phi = (p - 1) * (q - 1)
    if type(e) is not int or not (1 < e < phi) or gcd(e, phi) != 1:
        raise ValueError("e deve ser inteiro, 1 < e < phi e coprimo com phi")
    return p * q, pow(e, -1, phi)
 
def transformar(m, expoente, n):
    if type(m) is not int or not (0 <= m < n):
        raise ValueError("representante fora de 0..n-1 (não reduzir silenciosamente)")
    return pow(m, expoente, n)
 
n, d = preparar(7, 13, 5)
for m in range(n):
    assert transformar(transformar(m, 5, n), d, n) == m
 
# ---------- Parte 2: OAEP e PSS ----------
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
 
class Teste(unittest.TestCase):
    def test_1_todos_os_representantes(self):
        self.assertEqual((n, d), (91, 29))
        self.assertEqual(len({transformar(m, 5, n) for m in range(n)}), n)   # cifra é injetiva em 0..90
        for m in (0, 7, 13, 14, 26, 90):    # zero, múltiplos dos primos, n-1
            self.assertEqual(transformar(transformar(m, 5, n), d, n), m)
        for ruim in (-1, n, True, 2.0):
            with self.assertRaises(ValueError):
                transformar(ruim, 5, n)
        with self.assertRaises(ValueError):
            preparar(7, 13, 6)               # gcd(6, 72) = 6
 
    def test_2_maleabilidade(self):
        m, r = 9, 2
        c = transformar(m, 5, n)
        c_mod = (c * pow(r, 5, n)) % n
        self.assertEqual((c, c_mod), (81, 44))
        self.assertEqual(transformar(c_mod, d, n), (r * m) % n)   # 18
 
    def test_3_oaep(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        msg = b"pedido=7"
        c1, c2 = pub.encrypt(msg, OAEP), pub.encrypt(msg, OAEP)
        self.assertEqual((len(c1), len(c2)), (256, 256))
        self.assertNotEqual(c1, c2)                           # probabilístico
        self.assertEqual(priv.decrypt(c1, OAEP), msg)
        self.assertEqual(priv.decrypt(c2, OAEP), msg)
        self.assertEqual(priv.decrypt(pub.encrypt(b"A" * 190, OAEP), OAEP), b"A" * 190)
        with self.assertRaises(ValueError):
            pub.encrypt(b"A" * 191, OAEP)
        # extensão opcional: rótulos diferentes
        lab = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"outro")
        with self.assertRaises(ValueError):
            priv.decrypt(c1, lab)
 
    def test_4_pss(self):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        outra = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub, msg = priv.public_key(), b"pedido=7"
        sig = priv.sign(msg, PSS, hashes.SHA256())
        self.assertIsNone(pub.verify(sig, msg, PSS, hashes.SHA256()))   # sucesso = sem exceção
        with self.assertRaises(InvalidSignature):
            pub.verify(sig, b"pedido=8", PSS, hashes.SHA256())
        adulterada = bytes([sig[0] ^ 1]) + sig[1:]
        with self.assertRaises(InvalidSignature):
            pub.verify(adulterada, msg, PSS, hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            outra.public_key().verify(sig, msg, PSS, hashes.SHA256())
 
if __name__ == "__main__":
    unittest.main(verbosity=2)

