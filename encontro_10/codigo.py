import secrets, unittest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
 
MSG = b"nota=8.5"            
NONCE = b"\x00" * 12         
CTX = b"encontro10|v1|alice->bob"
 
def pub_bytes(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
 
def derivar(segredo, sal, contexto=CTX):
    # instância nova de HKDF a cada derivação
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sal, info=contexto).derive(segredo)
 
def acordo(priv_local, pub_remota_bytes):
    return priv_local.exchange(X25519PublicKey.from_public_bytes(pub_remota_bytes))
 
class TesteLab(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.m = (X25519PrivateKey.generate() for _ in range(3))
        self.A, self.B, self.M = pub_bytes(self.a), pub_bytes(self.b), pub_bytes(self.m)
        self.sal = secrets.token_bytes(16)
 
    # Tarefa 1
    def test_1_acordo_correto(self):
        sa, sb = acordo(self.a, self.B), acordo(self.b, self.A)
        self.assertEqual(len(sa), 32); self.assertEqual(len(sb), 32)
        self.assertEqual(sa, sb)
        self.assertNotEqual(sa, b"\x00" * 32)       # evita aceitar duas respostas "vazias"
        self.assertEqual((len(self.A), len(self.B)), (32, 32))
 
    # Tarefa 2
    def test_2_derivacao_e_aead(self):
        ka = derivar(acordo(self.a, self.B), self.sal)
        kb = derivar(acordo(self.b, self.A), self.sal)
        self.assertEqual(ka, kb)
        pacote = AESGCM(ka).encrypt(NONCE, MSG, None)
        self.assertEqual(len(pacote), 8 + 16)         # 8 bytes + etiqueta de 16
        self.assertEqual(AESGCM(kb).decrypt(NONCE, pacote, None), MSG)
 
    # Tarefa 3
    def test_3_substituicao_da_publica_de_alice(self):
        k_alice = derivar(acordo(self.a, self.M), self.sal)      # Alice recebeu M no lugar de B
        k_mallory = derivar(acordo(self.m, self.A), self.sal)
        k_bob = derivar(acordo(self.b, self.A), self.sal)
        self.assertEqual(k_alice, k_mallory)
        self.assertNotEqual(k_alice, k_bob)
        pacote = AESGCM(k_alice).encrypt(NONCE, MSG, None)
        self.assertEqual(AESGCM(k_mallory).decrypt(NONCE, pacote, None), MSG)   # Mallory abre
        with self.assertRaises(InvalidTag):
            AESGCM(k_bob).decrypt(NONCE, pacote, None)                          # Bob não abre
 
    # Tarefa 4
    def test_4_duas_conexoes(self):
        k_am = derivar(acordo(self.a, self.M), self.sal)          # Alice <-> Mallory
        k_bm = derivar(acordo(self.b, self.M), self.sal)          # Bob   <-> Mallory
        self.assertEqual(k_am, derivar(acordo(self.m, self.A), self.sal))
        self.assertEqual(k_bm, derivar(acordo(self.m, self.B), self.sal))
        self.assertNotEqual(k_am, k_bm)
        pacote_alice = AESGCM(k_am).encrypt(NONCE, MSG, None)
        aberto = AESGCM(k_am).decrypt(NONCE, pacote_alice, None)   # Mallory abre...
        pacote_bob = AESGCM(k_bm).encrypt(NONCE, aberto, None)     # ...e recifra com outra chave
        self.assertEqual(AESGCM(k_bm).decrypt(NONCE, pacote_bob, None), MSG)  # Bob não percebe
 
    # Tarefa 5
    def test_5_adulteracao_e_contexto(self):
        k = derivar(acordo(self.a, self.B), self.sal)
        pacote = AESGCM(k).encrypt(NONCE, MSG, None)
        adulterado = bytes([pacote[0] ^ 1]) + pacote[1:]
        with self.assertRaises(InvalidTag):
            AESGCM(k).decrypt(NONCE, adulterado, None)
        k_outro = derivar(acordo(self.b, self.A), self.sal, b"encontro10|v1|bob->alice")
        self.assertNotEqual(k, k_outro)
        with self.assertRaises(InvalidTag):
            AESGCM(k_outro).decrypt(NONCE, pacote, None)
 
if __name__ == "__main__":
    unittest.main(verbosity=2)


