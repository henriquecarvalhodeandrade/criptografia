import sys
from pathlib import Path

caminho_raiz = Path(__file__).resolve().parent.parent
if str(caminho_raiz) not in sys.path:
    sys.path.append(str(caminho_raiz))


from atividade_11.main import cesar, decifrar

def cifra_combinada(texto: str, k: int = 3) -> str:
    """Aplica substituicao de Cesar seguida de transposicao em duas colunas."""
    
    cifrado_cesar = cesar(texto, k)
  
    coluna_par = cifrado_cesar[0::2]
    coluna_impar = cifrado_cesar[1::2]

    return coluna_par + coluna_impar


def decifra_combinada(texto_cifrado: str, k: int = 3) -> str:
    """Inverte a transposicao colunar e decifra o texto resultante via Cesar."""
    n = len(texto_cifrado)
    metade = (n + 1) // 2

    coluna_par = texto_cifrado[:metade]
    coluna_impar = texto_cifrado[metade:]

    intercalado = []
    for i in range(len(coluna_par)):
        intercalado.append(coluna_par[i])
        if i < len(coluna_impar):
            intercalado.append(coluna_impar[i])

    texto_intermediario = "".join(intercalado)

    return decifrar(texto_intermediario, k)


mensagem_original = "CRIPTOGRAFIA"
chave_k = 3

cifrado = cifra_combinada(mensagem_original, k=chave_k)
decifrado = decifra_combinada(cifrado, k=chave_k)

print("--- Demonstracao do Desafio ---")
print(f"Original:  {mensagem_original}")
print(f"Cifrado:   {cifrado}")
print(f"Decifrado: {decifrado}")

assert decifrado == mensagem_original, "Erro na inversao da cifra combinada!"
print("\n[OK] Assercoes executadas com sucesso.")
