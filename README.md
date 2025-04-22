# Merkle Tree Validation with OpenMP

Este projeto implementa a **validação paralela de múltiplas transações** contra uma Merkle Tree pré-construída em C, utilizando a biblioteca OpenSSL (API EVP) para os cálculos de hash SHA-256 e OpenMP para paralelização.

O foco anterior era na construção da árvore, que mostrou ter potencial limitado de paralelização nível a nível. Este projeto agora foca em um cenário mais realista e paralelamente mais eficiente: **validar um grande conjunto de transações independentemente**.

**Abordagem:**

1.  **Leitura:** Lê as transações de um arquivo de entrada.
2.  **Construção (Sequencial):** Constrói a Merkle Tree completa na memória, armazenando todos os níveis e hashes. Esta é uma fase de pré-computação sequencial.
3.  **Geração de Provas (Sequencial):** Para cada transação lida, gera sua respectiva Prova Merkle (audit path) a partir da árvore completa. Esta também é uma fase de pré-computação sequencial.
4.  **Validação (Paralela):** Valida *cada* transação usando sua prova Merkle contra a raiz conhecida da árvore. **Este loop de validação é paralelizado usando OpenMP**, distribuindo as tarefas de validação entre as threads disponíveis.

**Objetivo:** Avaliar o ganho de desempenho (speedup, eficiência) obtido com a paralelização OpenMP na fase de validação para diferentes números de transações e threads.

## Arquivos Principais

*   `merkle_validation_common.h`: Header com definições de estruturas (`MerkleProof`, `FullMerkleTree`) e declarações de funções.
*   `merkle_validation_utils.c`: Implementações das funções auxiliares (hash, leitura, free) e das funções de construção da árvore completa e geração de provas.
*   `merkle_validation_sequential.c`: Implementação da validação sequencial (lê dados, constrói árvore, gera provas, valida em loop sequencial). Usado como **baseline** para medição de speedup.
*   `merkle_validation_parallel.c`: Implementação da validação paralela (lê dados, constrói árvore, gera provas - tudo sequencialmente; **valida em loop paralelo com OpenMP**).

*(Nota: Os arquivos `merkle_sequential.c` e `merkle_parallel.c` originais, focados na construção, permanecem no repositório como referência, mas não são o foco deste trabalho.)*

## Pré-requisitos

*   **Compilador C com Suporte a OpenMP:** GCC ou Clang (com runtime OpenMP instalado, ex: `libomp` ou via GCC no macOS).
*   **Bibliotecas de Desenvolvimento OpenSSL:** `libssl-dev` (Debian/Ubuntu) ou `openssl-devel` (Fedora/CentOS) ou via Homebrew (`openssl`).
*   **Bash Shell:** Para executar o script `benchmark.sh`.

## Arquivos de Dados

Utiliza os mesmos arquivos de dados (`data*.txt`) contendo uma transação por linha:

*   `data8.txt`
*   `data9.txt`
*   `data800.txt`
*   `data8000.txt`
*   `data80000.txt`

## Instalando Dependências

(Instruções de instalação permanecem as mesmas - `openssl` e compilador C)

*   **macOS (com Homebrew):**
    ```bash
    brew install openssl gcc
    # Use gcc-14 ou a versão instalada
    ```
*   **Linux (Debian/Ubuntu):**
    ```bash
    sudo apt-get update && sudo apt-get install build-essential libssl-dev
    ```
*   **Linux (Fedora/CentOS/RHEL):**
    ```bash
    sudo dnf update && sudo dnf install gcc openssl-devel
    ```

## Compilando Manualmente

Navegue até o diretório do projeto. Adapte o compilador e caminhos do OpenSSL se necessário.

**Exemplo - macOS (Apple Silicon com GCC 14):**

1.  **Compilar Utils:**
    ```bash
    gcc-14 -Wall -O2 -c merkle_validation_utils.c -o merkle_validation_utils.o -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm
    ```
2.  **Compilar Sequencial:**
    ```bash
    gcc-14 -Wall -O2 merkle_validation_sequential.c merkle_validation_utils.o -o merkle_validation_sequential -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm
    ```
3.  **Compilar Paralelo:**
    ```bash
    gcc-14 -Wall -O2 -fopenmp merkle_validation_parallel.c merkle_validation_utils.o -o merkle_validation_parallel -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm -fopenmp
    ```

**Exemplo - Linux (GCC):**

1.  **Compilar Utils:**
    ```bash
    gcc -Wall -O2 -c merkle_validation_utils.c -o merkle_validation_utils.o -lssl -lcrypto -lm
    ```
2.  **Compilar Sequencial:**
    ```bash
    gcc -Wall -O2 merkle_validation_sequential.c merkle_validation_utils.o -o merkle_validation_sequential -lssl -lcrypto -lm
    ```
3.  **Compilar Paralelo:**
    ```bash
    gcc -Wall -O2 -fopenmp merkle_validation_parallel.c merkle_validation_utils.o -o merkle_validation_parallel -lssl -lcrypto -lm -fopenmp
    ```

## Executando

Ambos os programas requerem o nome do arquivo de dados como argumento.

*   **Versão Sequencial (Baseline):**
    ```bash
    ./merkle_validation_sequential data8000.txt
    ```
    *Anote o "Tempo de execução da validação sequencial" para calcular o speedup.*

*   **Versão Paralela:**
    ```bash
    # Defina o número de threads (ex: 8)
    export OMP_NUM_THREADS=8
    ./merkle_validation_parallel data8000.txt
    ```
    *Anote o "Tempo de execução da validação paralela".*

## Benchmark de Desempenho

O script `benchmark.sh` automatiza a execução da versão **paralela** (`merkle_validation_parallel`) contra **todos** os arquivos de dados (`DATA_FILES`), variando o número de threads.

1.  **Compile a versão paralela (`merkle_validation_parallel`) e as utils (`merkle_validation_utils.o`) primeiro.**
2.  **Compile a versão sequencial (`merkle_validation_sequential`)** para obter os tempos base.
3.  **Certifique-se que os arquivos de dados (`data*.txt`) existem.**
4.  **Execute a versão sequencial UMA VEZ para CADA arquivo de dados** para obter os tempos `T_seq` de referência:
    ```bash
    ./merkle_validation_sequential data8.txt
    ./merkle_validation_sequential data9.txt
    ./merkle_validation_sequential data800.txt
    ./merkle_validation_sequential data8000.txt
    ./merkle_validation_sequential data80000.txt
    ```
5.  **Dê permissão de execução ao script de benchmark:**
    ```bash
    chmod +x benchmark.sh
    ```
6.  **Execute o script de benchmark (que roda a versão paralela):**
    ```bash
    ./benchmark.sh
    ```
    A saída mostrará os tempos da **validação paralela** para diferentes contagens de threads e arquivos. Colete esses tempos `T_par(N)`.
