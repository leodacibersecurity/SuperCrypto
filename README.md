# SuperCrypto
Um códigozinho que fiz no tédio. Criptografa e Descriptografa.

# AVISO!!!!!!
Para usar ele você vai prescisar de duas bibliotecas. 
A biblioteca Tkinker, para a interface gráfica e a cryptography para criptografar e descriptografar.
OBS: Você so vai prescisar delas se quiser mudar alguma coisa no software

## Funcionalidades

- Criptografia e descriptografia de texto usando métodos como Cifra de César, Cifra de Vigenère, AES, RSA e mais.
- Interface gráfica simples desenvolvida com Tkinker.
- Opções para copiar o texto criptografado e descriptografado para a área de transferência.
- Suporte para diferentes métodos de criptografia.

## Como Funciona

### 1. Estrutura do Código

O código é dividido em três partes principais:

1. **Interface Gráfica**: Criada com a biblioteca Kivy, a interface permite ao usuário interagir com o aplicativo, inserir texto, selecionar métodos de criptografia e visualizar os resultados.
2. **Módulos de Criptografia**: Implementam diferentes algoritmos de criptografia e descriptografia. Cada módulo é responsável por uma técnica específica, como Cifra de César, Cifra de Vigenère, AES e RSA.
3. **Lógica de Controle**: Gerencia a interação entre a interface gráfica e os módulos de criptografia. Ele lida com eventos do usuário, como clicar em botões, e chama as funções de criptografia apropriadas.

### 2. Funcionamento da Interface Gráfica

- **Entrada de Texto**: O usuário pode digitar o texto que deseja criptografar ou descriptografar.
- **Métodos de Criptografia**: O usuário escolhe o método de criptografia a partir de um menu suspenso. As opções incluem métodos como Cifra de César, Cifra de Vigenère, AES, e RSA.
- **Chave ou Deslocamento**: Dependendo do método selecionado, o usuário insere uma chave ou deslocamento necessário para a criptografia.
- **Botões de Ação**:
  - **Encrypt**: Criptografa o texto usando o método e chave fornecidos e exibe o texto criptografado.
  - **Decrypt**: Descriptografa o texto criptografado de volta ao texto original.
  - **Copy**: Copia o texto criptografado ou descriptografado para a área de transferência.

### 3. Métodos de Criptografia

#### Cifra de César

A Cifra de César é um dos métodos de criptografia mais simples e antigos. Ela desloca cada letra do alfabeto por um número fixo de posições. Por exemplo, com um deslocamento de 3, a letra 'A' se torna 'D'.

#### Cifra de Vigenère

A Cifra de Vigenère é uma melhoria da Cifra de César. Ela usa uma palavra-chave para determinar o deslocamento de cada letra, tornando a criptografia mais segura.

#### AES (Advanced Encryption Standard)

AES é um algoritmo de criptografia simétrica amplamente utilizado. Ele usa uma chave para criptografar e descriptografar o texto. AES é muito mais seguro do que métodos mais simples como a Cifra de César.

#### RSA (Rivest-Shamir-Adleman)

RSA é um algoritmo de criptografia assimétrica que usa um par de chaves, uma pública e uma privada. O texto é criptografado com a chave pública e descriptografado com a chave privada, garantindo segurança para a comunicação.

# Instalação
**Clone o repositório:**
   ```bash
   git clone https://github.com/usuario/projeto-criptografia.git
   cd projeto-criptografia
python3 supercripto.py
