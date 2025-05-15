# 🔐 Encriptador/Decriptador AES em C

Este é um projeto legado feito para a disciplina de **Criptografia** do curso de ciências da computação na Universidade Federal do Paraná. Ele não receberá atualizações e está sendo adicionado posterior a conclusão do curso no repositório apenas para fins de portifólio

Este é um projeto escrito em **C** que implementa a cifra **AES (Advanced Encryption Standard)** para encriptação e decriptação de arquivos. O programa é executado via linha de comando, permitindo que o usuário especifique o arquivo de entrada, a chave, e a operação desejada (encriptar ou decriptar).

## ⚙️ Funcionalidades

- **Encriptação AES de arquivos**
- **Decriptação AES de arquivos `.aes`**
- **Interface simples via terminal**
- Suporte a **chave fornecida via linha de comando**
- Geração de arquivo criptografado com a extensão `.aes`

## 📥 Como usar

### 🔧 Compilação

Compile o programa com `gcc`:

```bash
make
```

## 🚀 Execução

### 🔐 Encriptar um arquivo:

```bash
./aes -e -f arquivo.txt -p chave123
```

### 🔐 Decriptar um arquivo:
```bash
./aes -d -f arquivo.txt.aes -p chave123
```

## 📌 Parâmetros:

- -e: modo encriptação

- -d: modo decriptação

- -f: caminho do arquivo a ser processado

- -p: chave de 128 bits (16 caracteres) usada para a cifra AES

## 📤 Saída:

- O arquivo resultante da encriptação terá a extensão .aes
- A decriptação devolve um arquivo com o nome original, sem a extensão .aes
