SEGUNDOS_ANO = 365.25 * 24 * 60 * 60


def tempo_medio(bits_seguranca, testes_por_segundo, maquinas=1):
    # Usa metade do espaço de chaves como quantidade média de tentativas.
    tentativas_medias = 2 ** (bits_seguranca - 1)

    # Divide a taxa de testes entre as máquinas disponíveis.
    taxa_total = testes_por_segundo * maquinas

    return tentativas_medias / taxa_total


def em_anos(segundos):
    return segundos / SEGUNDOS_ANO


CENARIOS = [
    ("DES", 56),
    ("3DES (forca estimada)", 112),
    ("AES-128", 128),
]


# Teste fornecido pelo enunciado.
assert tempo_medio(56, 1e12) == 2 ** 55 / 1e12


print("=== Tempo medio com uma maquina ===")

for nome, bits in CENARIOS:
    segundos = tempo_medio(bits, 1e12)

    print(f"\n{nome}")
    print(f"Bits de seguranca: {bits}")
    print(f"Tempo em segundos: {segundos:.3e}")
    print(f"Tempo em anos: {em_anos(segundos):.3e}")


print("\n=== Teste com varias maquinas ===")

QUANTIDADES_MAQUINAS = [
    1,
    10 ** 3,
    10 ** 6,
    10 ** 9
]

for nome, bits in CENARIOS:
    print(f"\n{nome}")

    for maquinas in QUANTIDADES_MAQUINAS:
        segundos = tempo_medio(bits, 1e12, maquinas)

        print(
            f"{maquinas:.0e} maquinas -> "
            f"{segundos:.3e} segundos -> "
            f"{em_anos(segundos):.3e} anos"
        )


# Dobrar a quantidade de máquinas deve dividir o tempo por dois.
tempo_1_maquina = tempo_medio(56, 1e12, 1)
tempo_2_maquinas = tempo_medio(56, 1e12, 2)

assert tempo_2_maquinas == tempo_1_maquina / 2


# Adicionar um bit deve dobrar aproximadamente o tempo.
tempo_56_bits = tempo_medio(56, 1e12)
tempo_57_bits = tempo_medio(57, 1e12)

assert tempo_57_bits == tempo_56_bits * 2


# A razão entre 128 bits e 56 bits deve ser 2^72.
tempo_des = tempo_medio(56, 1e12)
tempo_aes = tempo_medio(128, 1e12)

razao = tempo_aes / tempo_des

assert razao == 2 ** 72


print("\nTodos os testes passaram.")

print(f"\nTempo medio DES: {tempo_des / 3600:.2f} horas")
print(f"Razao AES-128 / DES-56: 2^72 = {2 ** 72}")