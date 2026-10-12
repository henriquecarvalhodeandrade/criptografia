# Demonstração de criptografia com AES-GCM

Este projeto demonstra a criptografia e a descriptografia de uma mensagem utilizando **AES-256-GCM**. A atividade compara dois cenários: a recuperação da mensagem com a chave correta e a falha de autenticação quando é utilizada a chave de outro participante.

## Conceito utilizado

O AES é um algoritmo de criptografia **simétrica**. Isso significa que a mesma chave secreta é usada para criptografar e descriptografar a mensagem.

Neste projeto não existem chaves pública e privada. Cada integrante gera uma única chave AES secreta. O modo GCM foi escolhido porque oferece:

- **confidencialidade:** esconde o conteúdo da mensagem;
- **integridade:** detecta alterações no conteúdo criptografado;
- **autenticidade da mensagem:** verifica se o pacote foi produzido com a chave correta.

Se a chave estiver incorreta ou o pacote tiver sido modificado, a autenticação falha e nenhuma mensagem é liberada.

## Requisitos

- Python 3;
- pacote `cryptography`.

Instale a dependência com:

```bash
python -m pip install cryptography
```

## Arquivos do projeto

```text
gerar_pacote_aes.py
descriptografar_aes.py
```

Após executar o gerador, também será criada a seguinte estrutura:

```text
arquivos_para_enviar/
├── chave_aes.txt
└── mensagem_criptografada.json
```

### `gerar_pacote_aes.py`

Responsável por:

1. receber a mensagem digitada pelo usuário;
2. gerar uma chave AES de 256 bits;
3. gerar um nonce aleatório de 12 bytes;
4. criptografar a mensagem com AES-GCM;
5. criar os arquivos que serão enviados aos outros participantes.

### `descriptografar_aes.py`

É o script comum utilizado por todos os integrantes. Ele:

1. localiza o arquivo da chave e o pacote criptografado;
2. converte os valores em Base64 novamente para bytes;
3. tenta autenticar e descriptografar o pacote;
4. mostra a mensagem somente se a autenticação for bem-sucedida;
5. informa `InvalidTag` se a chave estiver incorreta ou o pacote tiver sido alterado.

### `chave_aes.txt`

Contém a chave secreta AES codificada em Base64. Base64 não é criptografia; é apenas uma representação textual dos bytes da chave.

### `mensagem_criptografada.json`

Contém:

- identificação do algoritmo utilizado;
- nonce em Base64;
- mensagem criptografada e etiqueta de autenticação em Base64.

A biblioteca `AESGCM` devolve o texto cifrado seguido da etiqueta de autenticação.

## Fluxo da atividade

### 1. Gerar a mensagem criptografada

O remetente executa:

```bash
python gerar_pacote_aes.py
```

O programa solicitará a mensagem:

```text
Digite a mensagem que será criptografada:
```

Depois da digitação, serão criados:

```text
arquivos_para_enviar/chave_aes.txt
arquivos_para_enviar/mensagem_criptografada.json
```

Cada execução gera uma nova chave e um novo nonce. Portanto, os arquivos antigos serão substituídos se o programa for executado novamente na mesma pasta.

### 2. Enviar os arquivos

O remetente envia aos demais participantes:

```text
descriptografar_aes.py
chave_aes.txt
mensagem_criptografada.json
```

O script de descriptografia é igual para todos. O que muda entre os testes é o arquivo `chave_aes.txt`.

### 3. Testar com a chave correta

O participante coloca os três arquivos na mesma pasta:

```text
descriptografar_aes.py
chave_aes.txt
mensagem_criptografada.json
```

Em seguida, executa:

```bash
python descriptografar_aes.py
```

Resultado esperado:

```text
Mensagem descriptografada com sucesso:
[mensagem original]
```

Nesse cenário, a chave utilizada é a mesma que criptografou a mensagem. Por isso, a etiqueta é validada e o conteúdo original é recuperado.

### 4. Testar com a chave incorreta

Um participante substitui o `chave_aes.txt` correto pela chave gerada por outro integrante, mantendo o mesmo `mensagem_criptografada.json`.

Depois, executa novamente:

```bash
python descriptografar_aes.py
```

Resultado esperado:

```text
Erro de autenticação (InvalidTag).
A chave está incorreta ou o arquivo criptografado foi alterado.
```

Como a chave não corresponde àquela usada durante a criptografia, a etiqueta de autenticação não pode ser validada. A biblioteca rejeita o pacote e não disponibiliza uma mensagem parcialmente descriptografada.

## Organização sugerida para o grupo

Cada integrante pode executar o gerador uma vez e conservar seu próprio par de arquivos:

```text
Integrante A: pacote A + chave A
Integrante B: pacote B + chave B
Integrante C: pacote C + chave C
```

Os testes podem ser organizados assim:

| Pacote testado | Chave utilizada | Resultado esperado |
|---|---|---|
| Pacote A | Chave A | Mensagem recuperada |
| Pacote A | Chave B | `InvalidTag` |
| Pacote B | Chave B | Mensagem recuperada |
| Pacote B | Chave C | `InvalidTag` |

## Evidências para apresentar

O grupo pode registrar:

1. a execução do gerador;
2. os dois arquivos produzidos;
3. a mensagem recuperada com a chave correta;
4. o erro `InvalidTag` com a chave de outro integrante;
5. uma breve explicação do motivo dos resultados.

## Explicação resumida

> Primeiro, o programa gera uma chave AES de 256 bits e um nonce aleatório. A mensagem é criptografada com AES-GCM, que também produz uma etiqueta de autenticação. Com a mesma chave utilizada na criptografia, o receptor valida a etiqueta e recupera a mensagem. Quando é usada a chave AES de outro integrante, a etiqueta não pode ser validada, a biblioteca gera `InvalidTag` e nenhuma mensagem é liberada.

## Observação de segurança

Nesta atividade, a chave é enviada junto com o pacote para permitir a demonstração em sala. Isso é aceitável apenas no contexto didático.

Em uma aplicação real, enviar a chave secreta pelo mesmo canal da mensagem elimina a confidencialidade contra alguém que tenha acesso aos dois arquivos. Sistemas reais precisam usar um canal seguro para distribuir a chave ou adotar um esquema híbrido com criptografia assimétrica.

O nonce não precisa ser secreto, mas não deve ser reutilizado com a mesma chave em uma nova criptografia AES-GCM.
