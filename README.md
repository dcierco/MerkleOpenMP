# Merkle Tree Construction with OpenMP

Este projeto implementa a construção de uma Merkle Tree em C, utilizando a biblioteca OpenSSL (API EVP) para os cálculos de hash SHA-256. Ele fornece duas versões:

1.  `merkle_sequential.c`: Uma implementação puramente sequencial.
2.  `merkle_parallel.c`: Uma implementação paralelizada usando diretivas OpenMP para acelerar o cálculo dos hashes em cada nível da árvore.

O objetivo é demonstrar e avaliar o ganho de desempenho obtido com a paralelização usando OpenMP em uma tarefa computacionalmente intensiva.

## Pré-requisitos

*   **Compilador C com Suporte a OpenMP:**
    *   **Linux:** GCC (geralmente incluído em `build-essential` ou `gcc`).
    *   **macOS:** Recomenda-se **instalar um compilador GCC via Homebrew** (ex: `brew install gcc`), pois o Clang padrão da Apple (identificado como `gcc` ou `cc` por padrão) **não** inclui o runtime OpenMP. Usaremos `gcc-14` como exemplo nos comandos abaixo, mas ajuste para a versão instalada (ex: `gcc-13`, `gcc-12`). **Não use o compilador padrão do sistema no macOS para a versão paralela.**
*   **Bibliotecas de Desenvolvimento OpenSSL:** Necessário para compilar o código que utiliza as funções de hash.
*   **Bash Shell:** Para executar o script `benchmark.sh`.

## Instalando Dependências

Você precisa instalar as dependências manualmente:

*   **macOS (com Homebrew):**
    ```bash
    # Instala/Atualiza Homebrew (se necessário)
    # /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Instala OpenSSL e um compilador GCC com OpenMP (ex: gcc-14)
    brew install openssl gcc
    # Anote a versão do GCC instalada (ex: 'gcc-14') para usar nos comandos de compilação.
    ```

*   **Linux (Debian/Ubuntu):**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libssl-dev
    # 'build-essential' geralmente inclui GCC com suporte a OpenMP. Use 'gcc' nos comandos.
    ```

*   **Linux (Fedora/CentOS/RHEL):**
    ```bash
    sudo dnf update # ou yum update
    sudo dnf install gcc openssl-devel # ou yum install gcc openssl-devel
    # Use 'gcc' nos comandos.
    ```

## Compilando Manualmente

Navegue até o diretório do projeto no terminal e use os seguintes comandos. **Adapte o nome do compilador e os caminhos do OpenSSL conforme seu sistema.**

**Compilador:**
*   Use `gcc` no Linux (se instalado pelos comandos acima).
*   Use a versão específica do GCC instalada pelo Homebrew no macOS (ex: `gcc-14`, `gcc-13`). **Não use `cc` ou o `gcc` padrão do macOS para a versão paralela.**

**Caminhos OpenSSL:**
*   **Linux:** Geralmente não é necessário especificar caminhos (`-I`, `-L`) se `libssl-dev`/`openssl-devel` foi instalado corretamente.
*   **macOS (Homebrew):** É **essencial** especificar os caminhos. Use `-I/opt/homebrew/opt/openssl/include` e `-L/opt/homebrew/opt/openssl/lib` (para Apple Silicon) ou `-I/usr/local/opt/openssl/include` e `-L/usr/local/opt/openssl/lib` (para Intel Mac).

---

**Exemplo de Compilação - macOS (Apple Silicon com GCC 14):**

*   **Sequencial:**
    ```bash
    gcc-14 -Wall -O2 -I/opt/homebrew/opt/openssl/include merkle_sequential.c -o merkle_sequential -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm
    ```
*   **Paralelo (Note a flag -fopenmp):**
    ```bash
    gcc-14 -Wall -O2 -fopenmp -I/opt/homebrew/opt/openssl/include merkle_parallel.c -o merkle_parallel -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm -fopenmp
    # Note: -fopenmp é necessário tanto para compilação quanto para link com GCC
    ```

---

**Exemplo de Compilação - Linux (Debian/Ubuntu/Fedora com GCC):**

*   **Sequencial:**
    ```bash
    gcc -Wall -O2 merkle_sequential.c -o merkle_sequential -lssl -lcrypto -lm
    ```
*   **Paralelo (Note a flag -fopenmp):**
    ```bash
    gcc -Wall -O2 -fopenmp merkle_parallel.c -o merkle_parallel -lssl -lcrypto -lm -fopenmp
    ```

---

*(Use `-Wall -O2` para habilitar warnings úteis e otimizações básicas)*

## Executando

*   **Versão Sequencial:**
    ```bash
    ./merkle_sequential
    ```
*   **Versão Paralela:**
    ```bash
    # Define o número de threads (ex: 4)
    export OMP_NUM_THREADS=4
    ./merkle_parallel
    ```
    *(O programa imprimirá o número de threads usado e o tempo de execução)*

## Benchmark de Desempenho

O script `benchmark.sh` automatiza a execução da versão paralela com diferentes números de threads (de 1 até o número de cores lógicos detectados).

1.  **Compile a versão paralela (`merkle_parallel`) primeiro.**
2.  **Dê permissão de execução ao script:**
    ```bash
    chmod +x benchmark.sh
    ```
3.  **Execute o script:**
    ```bash
    ./benchmark.sh
    ```
    O script imprimirá a saída de cada execução, incluindo o tempo. Colete esses tempos para calcular Speedup e Eficiência.

## Observação Importante sobre Desempenho

Com o conjunto de dados de exemplo (8 transações), o overhead do OpenMP (criação e sincronização de threads) provavelmente será **maior** que o tempo de cálculo dos hashes, resultando em *slowdown* (tempo aumenta com mais threads).

Para observar os **benefícios** da paralelização (speedup), **é essencial aumentar significativamente o número de transações** no array `transactions` dentro do `main()` em ambos os arquivos `.c`. Experimente com centenas ou milhares de transações para que o trabalho computacional domine o overhead.
