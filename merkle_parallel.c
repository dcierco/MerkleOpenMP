#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <omp.h>

// Define o tamanho do hash SHA-256 em bytes e caracteres hexadecimais
#define HASH_BYTES 32
#define HASH_LEN (HASH_BYTES * 2)
#define HASH_STR_SIZE (HASH_LEN + 1)

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
 *        Esta função é chamada por cada thread, mas seu conteúdo não é paralelizado internamente aqui.
 * @param input1 Primeira string de entrada.
 * @param input2 Segunda string de entrada (ou NULL).
 * @param output_hex Buffer para o hash hexadecimal resultante.
 * @return int 0 em sucesso, -1 em erro.
 */
int calculate_sha256_hash_evp(const char* input1, const char* input2, char* output_hex) {
    EVP_MD_CTX *md_ctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char hash_raw[HASH_BYTES];
    unsigned int hash_len_raw;
    int success = -1; // Assume erro inicialmente

    md = EVP_sha256();
    if (md == NULL) { handle_openssl_errors(); goto cleanup; }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) { handle_openssl_errors(); goto cleanup; }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) { handle_openssl_errors(); goto cleanup; }

    if (EVP_DigestUpdate(md_ctx, input1, strlen(input1)) != 1) { handle_openssl_errors(); goto cleanup; }

    if (input2 != NULL) {
        if (EVP_DigestUpdate(md_ctx, input2, strlen(input2)) != 1) { handle_openssl_errors(); goto cleanup; }
    }

    if (EVP_DigestFinal_ex(md_ctx, hash_raw, &hash_len_raw) != 1) { handle_openssl_errors(); goto cleanup; }

    if (hash_len_raw != HASH_BYTES) {
        fprintf(stderr, "Erro: Tamanho inesperado do hash (%u bytes).\n", hash_len_raw);
        goto cleanup;
    }

    // Converte hash binário para hexadecimal
    for (unsigned int i = 0; i < hash_len_raw; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash_raw[i]);
    }
    output_hex[HASH_LEN] = '\0';
    success = 0; // Sucesso

cleanup:
    if (md_ctx != NULL) EVP_MD_CTX_free(md_ctx);
    // Preenche saída com erro se necessário
    if (success != 0) { memset(output_hex, 'E', HASH_LEN); output_hex[HASH_LEN] = '\0'; }
    return success;
}

/**
 * @brief Libera a memória alocada para um nível da árvore (array de strings de hash).
 */
void free_level(char** level, int count) {
    if (!level) return;
    for (int i = 0; i < count; i++) {
        free(level[i]); // free(NULL) é seguro
    }
    free(level);
}

/**
 * @brief Constrói a Merkle Tree paralelamente com OpenMP usando SHA-256 via API EVP.
 *        Os cálculos de hash dentro de cada nível são paralelizados.
 * @param data_blocks Array de strings representando os blocos de dados iniciais.
 * @param num_blocks Número de blocos de dados.
 * @return char* String contendo o hash SHA-256 hexadecimal da Merkle Root.
 *               O chamador é responsável por liberar esta string com free().
 *               Retorna NULL em caso de erro (alocação ou cálculo de hash).
 */
char* build_merkle_tree_parallel_evp(const char* data_blocks[], int num_blocks) {
    if (num_blocks <= 0) {
        fprintf(stderr, "Erro: Nenhum bloco de dados fornecido.\n");
        return NULL;
    }

    // Flag compartilhada para sinalizar erro ocorrido em qualquer thread paralela.
    // Inicializada como 0 (sem erro).
    int error_occurred = 0;

    // --- Nível 0: Hashes das folhas ---
    char** current_level_hashes = (char**)malloc(num_blocks * sizeof(char*));
    if (!current_level_hashes) {
        perror("Erro ao alocar memória para ponteiros do nível 0");
        return NULL;
    }
    // Inicializa ponteiros com NULL para desalocação segura em caso de erro
    for(int i=0; i<num_blocks; ++i) current_level_hashes[i] = NULL;

    // Paraleliza o cálculo dos hashes das folhas usando OpenMP
    #pragma omp parallel for
    for (int i = 0; i < num_blocks; i++) {
        // Se um erro já ocorreu em outra thread, esta thread pode parar de trabalhar.
        // (Leitura atômica não estritamente necessária aqui, pois só paramos iterações futuras)
        if (error_occurred) continue;

        current_level_hashes[i] = (char*)malloc(HASH_STR_SIZE * sizeof(char));
        if (!current_level_hashes[i]) {
            // Usa omp critical para garantir que a flag de erro seja definida
            // e a mensagem seja impressa atomicamente (evita saídas misturadas).
            #pragma omp critical
            {
                if (!error_occurred) { // Evita mensagens repetidas
                   perror("Erro Malloc Folha (Paralelo)");
                   error_occurred = 1; // Sinaliza o erro globalmente
                }
            }
        } else {
            // Calcula o hash da folha i
            if (calculate_sha256_hash_evp(data_blocks[i], NULL, current_level_hashes[i]) != 0) {
                #pragma omp critical
                {
                    if (!error_occurred) {
                       fprintf(stderr, "Erro hash folha (Paralelo) Bloco %d.\n", i);
                       error_occurred = 1; // Sinaliza o erro globalmente
                    }
                }
                 // Marca o hash como inválido (ajuda na depuração, mas a flag é o principal)
                 memset(current_level_hashes[i], 'F', HASH_LEN);
                 current_level_hashes[i][HASH_LEN] = '\0';
            }
        }
    } // Fim do parallel for (barreira implícita aqui)

    // Após todas as threads terminarem, verifica se algum erro ocorreu no nível 0
    if (error_occurred) {
        fprintf(stderr, "Erro detectado durante o cálculo das folhas. Abortando.\n");
        free_level(current_level_hashes, num_blocks); // Limpa memória alocada
        return NULL; // Retorna erro para o chamador
    }

    int num_nodes_current_level = num_blocks;

    // --- Níveis Intermediários e Raiz (Loop sequencial entre níveis) ---
    while (num_nodes_current_level > 1 && !error_occurred) {
        int num_nodes_next_level = (int)ceil((double)num_nodes_current_level / 2.0);
        char** next_level_hashes = (char**)malloc(num_nodes_next_level * sizeof(char*));
        if (!next_level_hashes) {
            perror("Erro ao alocar memória para ponteiros do próximo nível");
            free_level(current_level_hashes, num_nodes_current_level);
            return NULL;
        }
        for(int i=0; i<num_nodes_next_level; ++i) next_level_hashes[i] = NULL;

        // Paraleliza o cálculo dos hashes para o próximo nível
        #pragma omp parallel for
        for (int i = 0; i < num_nodes_next_level; i++) {
            if (error_occurred) continue; // Outra thread já detectou erro

            // Índices dos filhos no nível anterior (leitura segura)
            int left_child_idx = 2 * i;
            int right_child_idx = 2 * i + 1;
            const char* left_hash = current_level_hashes[left_child_idx];
            const char* right_hash;

            // Trata o caso de nível com número ímpar de nós
            if (right_child_idx < num_nodes_current_level) {
                right_hash = current_level_hashes[right_child_idx];
            } else {
                right_hash = left_hash; // Duplica o último hash
            }

            // Aloca memória para o hash do nó atual (no próximo nível)
            next_level_hashes[i] = (char*)malloc(HASH_STR_SIZE * sizeof(char));
            if (!next_level_hashes[i]) {
                #pragma omp critical
                {
                    if(!error_occurred){
                       perror("Erro Malloc Nó Interno (Paralelo)");
                       error_occurred = 1; // Sinaliza erro
                    }
                }
            } else {
                // Calcula o hash combinando os dois filhos
                if (calculate_sha256_hash_evp(left_hash, right_hash, next_level_hashes[i]) != 0) {
                    #pragma omp critical
                    {
                        if(!error_occurred){
                           fprintf(stderr, "Erro hash nó interno (Paralelo) %d.\n", i);
                           error_occurred = 1; // Sinaliza erro
                        }
                    }
                    memset(next_level_hashes[i], 'F', HASH_LEN);
                    next_level_hashes[i][HASH_LEN] = '\0';
                }
            }
        } // Fim do parallel for (barreira implícita aqui)

        // Verifica se erro ocorreu durante o cálculo deste nível
        if (error_occurred) {
            fprintf(stderr, "Erro detectado durante cálculo de nível intermediário. Abortando.\n");
            free_level(next_level_hashes, num_nodes_next_level); // Limpa nível atual (parcial)
            free_level(current_level_hashes, num_nodes_current_level); // Limpa nível anterior
            return NULL;
        }

        // Libera a memória do nível anterior completo e sem erros
        free_level(current_level_hashes, num_nodes_current_level);

        // Avança: o próximo nível agora é o nível atual
        current_level_hashes = next_level_hashes;
        num_nodes_current_level = num_nodes_next_level;
    } // Fim do while (construção nível a nível)

    // Se saímos do while devido a erro, a flag estará definida
    if (error_occurred) {
       // A limpeza já foi feita dentro do loop while na checagem de erro
       return NULL;
    }

    // Se tudo correu bem, a raiz é o único hash restante no nível atual
    char* merkle_root = current_level_hashes[0];
    free(current_level_hashes); // Libera o array de ponteiros (que contém apenas a raiz)

    return merkle_root; // Retorna a string da raiz (chamador deve liberar)
}

int main() {
    // Dados de exemplo
    const char* transactions[] = {
        "Alice pays Bob 10 BTC", "Bob pays Carol 5 BTC", "Carol pays David 2 BTC",
        "David pays Eve 1 BTC", "Eve pays Alice 3 BTC", "Fernando pays Gus 8 BTC",
        "Gus pays Hebe 1 BTC", "Hebe pays Ivan 4 BTC"
        // "Ivan pays Joana 7 BTC" // Para testar com ímpar
    };
    int num_transactions = sizeof(transactions) / sizeof(transactions[0]);

    // TODO: Considerar aumentar num_transactions para benchmarks mais significativos
    //       (ex: duplicar o array, ler de arquivo)

    printf("Construindo Merkle Tree com SHA-256 (OpenSSL EVP) para %d transações...\n", num_transactions);

    // Variáveis para medição de tempo e número de threads
    double start_time, end_time, time_spent;
    int num_threads_used;

    printf("\n--- Execução Paralela ---\n");
    start_time = omp_get_wtime(); // Inicia cronômetro OpenMP

    // Chama a função PARALELA para construir a árvore
    char* root_hash = build_merkle_tree_parallel_evp(transactions, num_transactions);

    end_time = omp_get_wtime(); // Para cronômetro OpenMP
    time_spent = end_time - start_time;

    // Obtém o número máximo de threads que o OpenMP foi configurado para usar
    num_threads_used = omp_get_max_threads();

    // Verifica o resultado e imprime informações
    if (root_hash) {
        printf("------------------------------------------------------------------\n");
        printf("Merkle Root (Parallel, SHA-256 EVP): %s\n", root_hash);
        printf("------------------------------------------------------------------\n");
        printf("Tempo de execução Paralela com %d threads: %f segundos\n", num_threads_used, time_spent);
        free(root_hash); // Libera a string da raiz retornada
    } else {
        printf("Falha ao construir a Merkle Tree (erro interno detectado).\n");
        return 1; // Retorna código de erro
    }

    return 0; // Sucesso
}
