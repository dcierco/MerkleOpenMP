#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>

// --- Configuração de Hash (SHA-256 via EVP) ---
// SHA-256 produz um hash de 256 bits = 32 bytes.
// Representado em hexadecimal, são 64 caracteres.
#define HASH_BYTES 32 // 32 bytes = 256 bits
#define HASH_LEN (HASH_BYTES * 2)      // 64 caracteres hex
#define HASH_STR_SIZE (HASH_LEN + 1)    // +1 para o caractere nulo '\0'


/**
 * @brief Imprime os erros da pilha de erros da OpenSSL.
 */
void handle_openssl_errors(void) {
    unsigned long err_code;
    fprintf(stderr, "Erro OpenSSL: ");
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "%s\n", err_buf);
    }
}


/**
 * @brief Calcula o hash SHA-256 das entradas concatenadas usando a API EVP.
 *
 * @param input1 Primeira string de entrada (dado original ou hash filho esquerdo).
 * @param input2 Segunda string de entrada (hash filho direito, ou NULL para folhas).
 * @param output_hex Buffer (char array) onde o hash SHA-256 hexadecimal será escrito.
 *                   Deve ter tamanho HASH_STR_SIZE.
 * @return int 0 em sucesso, -1 em erro.
 */
int calculate_sha256_hash_evp(const char* input1, const char* input2, char* output_hex) {
    EVP_MD_CTX *md_ctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char hash_raw[HASH_BYTES]; // Buffer para o hash binário (32 bytes)
    unsigned int hash_len_raw; // Comprimento real do hash retornado

    int success = -1;

    // 1. Obter o algoritmo de digest (SHA-256)
    md = EVP_sha256();
    if (md == NULL) {
        fprintf(stderr, "Erro: EVP_sha256() falhou.\n");
        handle_openssl_errors();
        goto cleanup; // Pula para a limpeza
    }

    // 2. Criar e inicializar o contexto de digest
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "Erro: EVP_MD_CTX_new() falhou.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // 3. Inicializar a operação de digest
    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
        fprintf(stderr, "Erro: EVP_DigestInit_ex() falhou.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // 4. Atualizar com o primeiro input
    if (EVP_DigestUpdate(md_ctx, input1, strlen(input1)) != 1) {
        fprintf(stderr, "Erro: EVP_DigestUpdate() para input1 falhou.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // 5. Se houver um segundo input, atualizar com ele (concatenação)
    if (input2 != NULL) {
        if (EVP_DigestUpdate(md_ctx, input2, strlen(input2)) != 1) {
            fprintf(stderr, "Erro: EVP_DigestUpdate() para input2 falhou.\n");
            handle_openssl_errors();
            goto cleanup;
        }
    }

    // 6. Finalizar o cálculo e obter o hash binário
    if (EVP_DigestFinal_ex(md_ctx, hash_raw, &hash_len_raw) != 1) {
        fprintf(stderr, "Erro: EVP_DigestFinal_ex() falhou.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // Verificar se o tamanho do hash é o esperado (deve ser para SHA-256)
    if (hash_len_raw != HASH_BYTES) {
        fprintf(stderr, "Erro: Tamanho inesperado do hash (%u bytes) retornado por EVP_DigestFinal_ex.\n", hash_len_raw);
        goto cleanup;
    }

    // 7. Converter o hash binário (hash_raw) para string hexadecimal (output_hex)
    for (unsigned int i = 0; i < hash_len_raw; i++) {
        // sprintf para formatar cada byte como 2 caracteres hexadecimais
        sprintf(output_hex + (i * 2), "%02x", hash_raw[i]);
    }
    output_hex[HASH_LEN] = '\0'; // Garante a terminação nula da string

    success = 0;

cleanup:
    // 8. Liberar o contexto
    if (md_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx);
    }

    // Se houve erro antes da conversão, preenche com 'E' de Erro
    if (success != 0) {
         memset(output_hex, 'E', HASH_LEN);
         output_hex[HASH_LEN] = '\0';
    }

    return success;
}

// --- Estrutura da Merkle Tree ---

/**
 * @brief Libera a memória alocada para um nível da árvore.
 */
void free_level(char** level, int count) {
    if (!level) return;
    for (int i = 0; i < count; i++) {
        free(level[i]);
    }
    free(level);
}

/**
 * @brief Constrói a Merkle Tree sequencialmente usando SHA-256 via API EVP.
 *
 * @param data_blocks Array de strings representando os blocos de dados.
 * @param num_blocks Número de blocos de dados.
 * @return char* String contendo o hash SHA-256 hexadecimal da Merkle Root.
 *               O chamador é responsável por liberar esta string com free().
 *               Retorna NULL em caso de erro na construção ou no hash.
 */
char* build_merkle_tree_sequential_evp(const char* data_blocks[], int num_blocks) {
    if (num_blocks <= 0) {
        fprintf(stderr, "Erro: Nenhum bloco de dados fornecido.\n");
        return NULL;
    }

    // --- Nível 0: Hashes das folhas ---
    char** current_level_hashes = (char**)malloc(num_blocks * sizeof(char*));
    if (!current_level_hashes) {
        perror("Erro ao alocar memória para o nível 0");
        return NULL;
    }
    // Inicializar ponteiros para NULL para limpeza segura em caso de erro parcial
    for(int i=0; i<num_blocks; ++i) current_level_hashes[i] = NULL;

    // Calcula o hash SHA-256 (EVP) de cada bloco de dados (folhas)
    // POTENCIAL DE PARALELISMO AQUI
    for (int i = 0; i < num_blocks; i++) {
        current_level_hashes[i] = (char*)malloc(HASH_STR_SIZE * sizeof(char));
        if (!current_level_hashes[i]) {
            perror("Erro ao alocar memória para o hash da folha");
            free_level(current_level_hashes, num_blocks); // Usa num_blocks porque inicializamos com NULL
            return NULL;
        }
        // Calcula o hash SHA-256 (EVP) do bloco de dados i
        if (calculate_sha256_hash_evp(data_blocks[i], NULL, current_level_hashes[i]) != 0) {
             fprintf(stderr, "Erro ao calcular hash da folha para o bloco %d.\n", i);
             free_level(current_level_hashes, num_blocks);
             return NULL;
        }
        // printf("Leaf %d: %s (from data: %s)\n", i, current_level_hashes[i], data_blocks[i]); // Debug
    }

    int num_nodes_current_level = num_blocks;

    // --- Níveis Intermediários e Raiz ---
    while (num_nodes_current_level > 1) {
        int num_nodes_next_level = (int)ceil((double)num_nodes_current_level / 2.0);
        char** next_level_hashes = (char**)malloc(num_nodes_next_level * sizeof(char*));
        if (!next_level_hashes) {
            perror("Erro ao alocar memória para o próximo nível");
            free_level(current_level_hashes, num_nodes_current_level);
            return NULL;
        }
        // Inicializar ponteiros para NULL para limpeza segura
        for(int i=0; i<num_nodes_next_level; ++i) next_level_hashes[i] = NULL;

        // Calcula os hashes SHA-256 (EVP) para o próximo nível
        // POTENCIAL DE PARALELISMO AQUI
        for (int i = 0; i < num_nodes_next_level; i++) {
            next_level_hashes[i] = (char*)malloc(HASH_STR_SIZE * sizeof(char));
            if (!next_level_hashes[i]) {
                perror("Erro ao alocar memória para o hash do nó interno");
                free_level(next_level_hashes, num_nodes_next_level);
                free_level(current_level_hashes, num_nodes_current_level);
                return NULL;
            }

            int left_child_idx = 2 * i;
            int right_child_idx = 2 * i + 1;
            const char* left_hash = current_level_hashes[left_child_idx];
            const char* right_hash;

            if (right_child_idx < num_nodes_current_level) {
                right_hash = current_level_hashes[right_child_idx];
            } else {
                right_hash = left_hash; // Duplica hash ímpar
            }

            // Calcula o hash SHA-256 (EVP) do par concatenado
             if (calculate_sha256_hash_evp(left_hash, right_hash, next_level_hashes[i]) != 0) {
                 fprintf(stderr, "Erro ao calcular hash do nó interno %d.\n", i);
                 free_level(next_level_hashes, num_nodes_next_level);
                 free_level(current_level_hashes, num_nodes_current_level);
                 return NULL;
            }
            // printf("Level Node %d: %s (from %s + %s)\n", i, next_level_hashes[i], left_hash, right_hash); // Debug
        }

        // Libera a memória do nível atual
        free_level(current_level_hashes, num_nodes_current_level);

        // Avança para o próximo nível
        current_level_hashes = next_level_hashes;
        num_nodes_current_level = num_nodes_next_level;
    }

    // A raiz é o único nó restante
    char* merkle_root = current_level_hashes[0];
    free(current_level_hashes); // Libera o array de ponteiros, mas não a string da raiz

    return merkle_root; // Chamador deve liberar esta string
}

int main() {
    // Dados de exemplo
    const char* transactions[] = {
        "Alice pays Bob 10 BTC",
        "Bob pays Carol 5 BTC",
        "Carol pays David 2 BTC",
        "David pays Eve 1 BTC",
        "Eve pays Alice 3 BTC",
        "Fernando pays Gus 8 BTC",
        "Gus pays Hebe 1 BTC",
        "Hebe pays Ivan 4 BTC"
        // "Ivan pays Joana 7 BTC" // Descomente para testar com ímpar
    };
    int num_transactions = sizeof(transactions) / sizeof(transactions[0]);

    printf("Construindo Merkle Tree com SHA-256 (OpenSSL) para %d transações...\n", num_transactions);

    // Medir o tempo
    clock_t start = clock();

    // Chama a função sequencial para construir a árvore
    char* root_hash = build_merkle_tree_sequential_evp(transactions, num_transactions);

    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;


    if (root_hash) {
        printf("------------------------------------------------------------------\n");
        printf("Merkle Root (Sequencial, SHA-256): %s\n", root_hash);
        printf("------------------------------------------------------------------\n");
        printf("Tempo de execução sequencial: %f segundos\n", time_spent);

        // Libera a memória da string retornada pela função
        free(root_hash);
    } else {
        printf("Falha ao construir a Merkle Tree.\n");
        return 1;
    }

    return 0;
}
