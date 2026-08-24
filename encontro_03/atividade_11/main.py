ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def cesar(texto: str, chave: int):
    """
    Cifra ou decifra um texto deslocando os caracteres do alfabeto em 'chave' posicoes.
    Mantem caracteres fora do alfabeto inalterados (espacos, pontuacao, etc.).
    """
    resultado = []
    for caractere in texto.upper():
        if caractere in ALFABETO:
            indice_atual = ALFABETO.index(caractere)
            novo_indice = (indice_atual + chave) % 26
            resultado.append(ALFABETO[novo_indice])
        else:
            resultado.append(caractere)
    return "".join(resultado)


def decifrar(texto: str, chave: int):
    """
    Decifra o texto reutilizando a funcao cesar com o deslocamento inverso (-chave).
    """
    return cesar(texto, -chave)


def calcular_pontuacao(texto: str):
    """
    Pontua a probabilidade de uma string ser um texto legivel em portugues,
    favorecendo a ocorrencia de palavras comuns (stopwords).
    """
    palavras_chave = ["DE", "A", "QUE", "AO", "E", "O", "DO", "DA", "EM", "UM", "PARA"]
    palavras_texto = texto.split()
    pontuacao = sum(palavras_texto.count(p) for p in palavras_chave)
    return pontuacao


def candidatas(texto_cifrado: str):
    """
    Gera as 26 hipoteses de decifracao por busca exaustiva (forca bruta)
    e as ordena da mais provavel para a menos provavel baseando-se na pontuacao linguistica.
    Retorna uma lista de tuplas: (chave_testada, texto_decifrado, pontuacao).
    """
    hipoteses = []
    for chave in range(26):
        texto_decifrado = decifrar(texto_cifrado, chave)
        score = calcular_pontuacao(texto_decifrado)
        hipoteses.append((chave, texto_decifrado, score))
    
    hipoteses_ordenadas = sorted(hipoteses, key=lambda x: x[2], reverse=True)
    return hipoteses_ordenadas


segredo = cesar("ATAQUE AO AMANHECER", 7)
assert decifrar(segredo, 7) == "ATAQUE AO AMANHECER", "Falha no teste de decifracao!"

print(f"Texto cifrado: {segredo}")
print("Top 5 Hipoteses mais provaveis:")

ranking = candidatas(segredo)

for chave, texto, score in ranking[:5]:
    print(f"Chave {chave:02d} | Pontuacao: {score} | Texto: {texto}")
