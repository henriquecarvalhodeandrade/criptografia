"""
    Introducao a Criptografia
    Exercicios de codigo Python - Encontro 05 
    Henrique C. de Andrade JC3033732
    01/09/2026
"""

# ///////////////////////////////////////////////////////////////////////////

def f(metade, subchave):
    return (metade + subchave) % 256


def rodada(esquerda, direita, subchave):

    # (L, R) -> (R, L XOR F(R, K))
    nova_esquerda = direita
    nova_direita = esquerda ^ f(direita, subchave)

    return nova_esquerda, nova_direita


def cifrar(bloco, subchaves):

    # separa o bloco de 16 bits em duas metades de 8 bits
    esquerda = (bloco >> 8) & 0xFF
    direita = bloco & 0xFF

    for subchave in subchaves:
        esquerda, direita = rodada(esquerda, direita, subchave)

    return (esquerda << 8) | direita


def decifrar(bloco, subchaves):

    # percorre as subchaves em ordem inversa e desfaz cada rodada
    esquerda = (bloco >> 8) & 0xFF
    direita = bloco & 0xFF

    for subchave in reversed(subchaves):
        nova_direita = esquerda
        nova_esquerda = direita ^ f(nova_direita, subchave)
        esquerda, direita = nova_esquerda, nova_direita

    return (esquerda << 8) | direita


chaves = [3, 17, 91, 201]

for bloco in [0x0000, 0x1234, 0xFFFF]:
    assert decifrar(cifrar(bloco, chaves), chaves) == bloco

print("Todos os testes passaram")


# ///////////////////////////////////////////////////////////////////////////////////


bloco = 0x1234
bloco_bit_invertido = bloco ^ 0x0001  

c1 = cifrar(bloco, chaves)
c2 = cifrar(bloco_bit_invertido, chaves)

diff = c1 ^ c2
bits_diferentes = bin(diff).count("1")

print(f"C1 = {c1:016b}")
print(f"C2 = {c2:016b}")
print(f"diff = {diff:016b}")
print(f"bits diferentes: {bits_diferentes} de 16 ({bits_diferentes/16*100:.1f}%)")


# C1 = 0111100001000011
# C2 = 0100001100000010
# diff = 0011101101000001
# bits diferentes: 7 de 16 (43.8%)

"""
    43.8% ficou proximo, mas abaixo, dos 50% esperados pelo efeito
    avalanche. Isso e esperado em uma cifra de brinquedo com apenas quatro
    rodadas e uma funcao F muito simples (soma modular). 
    
    Com poucas rodadas e uma funcao F fraca, a difusao ainda nao "espalhou" completamente a
    diferenca do bit invertido por todas as posicoes de saida; um numero maior
    de rodadas, ou uma funcao F com melhor mistura, tenderia a aproximar o
    resultado de 50% em uma media sobre muitas entradas. 
    
    Por isso, quatro rodadas desta funcao nao formam uma cifra segura: a funcao F(R,K) = (R+K)
    mod 256 e linear (uma simples adicao modular), o que facilita relacoes
    algebricas simples entre entrada, chave e saida, alem de nao garantir
    confusao suficiente.
"""

# /////////////////////////////////////////////////////////////////////////////

"""
    Proponha uma funcao F deliberadamente fraca e explique por que varias
    rodadas Feistel ainda podem continuar inseguras.
"""

def f_fraca(metade, subchave):
    return metade

"""
    Com F(R, K) = R (independente da subchave), cada rodada apenas troca as
    metades e faz R_novo = L XOR R. Mesmo compondo varias dessas rodadas, a
    transformacao resultante e uma combinacao linear (XOR) fixa das metades
    originais, que nao depende de forma alguma da chave.
    
    Um atacante que observa pares (entrada, saida) consegue deduzir a estrutura da cifra sem
    nenhum conhecimento das subchaves, e diferentes chaves produzem exatamente
    a mesma transformacao. Alem disso, como XOR e uma operacao linear, o
    sistema inteiro (por mais rodadas que tenha) permanece solucionavel por
    algebra linear simples. 
    
    Isso ilustra que aumentar o numero de rodadas nao
    corrige uma funcao interna estruturalmente fraca: a seguranca depende da
    qualidade de F (nao linearidade, dependencia real da subchave, boa mistura)
    tanto quanto da quantidade de rodadas.
"""
