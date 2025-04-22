#include "merkle_validation_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <openssl/evp.h> // Certifique-se que estes estão incluídos
#include <openssl/err.h>

// --- Implementações das Funções Auxiliares ---

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
    fprintf(stderr, "\n"); // Adiciona uma nova linha no final
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

    for (unsigned int i = 0; i < hash_len_raw; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash_raw[i]);
    }
    output_hex[HASH_LEN] = '\0';
    success = 0; // Sucesso

cleanup:
    if (md_ctx != NULL) EVP_MD_CTX_free(md_ctx);
    if (success != 0) { memset(output_hex, 'E', HASH_LEN); output_hex[HASH_LEN] = '\0'; }
    return success;
}

/**
 * @brief Libera a memória alocada para uma estrutura MerkleProof.
 */
void free_merkle_proof(MerkleProof* proof) {
    if (!proof) return;
    if (proof->sibling_hashes) {
        for (int i = 0; i < proof->proof_length; i++) {
            free(proof->sibling_hashes[i]); // Libera cada string de hash
        }
        free(proof->sibling_hashes); // Libera o array de ponteiros
    }
    free(proof->sibling_positions); // Libera o array de posições
    free(proof); // Libera a estrutura principal
}

/**
 * @brief Libera a memória alocada para uma estrutura FullMerkleTree.
 */
void free_full_merkle_tree(FullMerkleTree* tree) {
    if (!tree) return;
    if (tree->all_levels) {
        for (int level = 0; level < tree->height; level++) {
            if (tree->all_levels[level]) {
                int num_nodes = tree->nodes_per_level[level];
                for (int i = 0; i < num_nodes; i++) {
                    free(tree->all_levels[level][i]); // Libera cada string de hash
                }
                free(tree->all_levels[level]); // Libera o array de ponteiros do nível
            }
        }
        free(tree->all_levels); // Libera o array de ponteiros para os níveis
    }
    free(tree->nodes_per_level); // Libera o array de contagem de nós
    free(tree->root_hash); // Libera a string da raiz
    free(tree); // Libera a estrutura principal
}

/**
 * @brief Libera a memória alocada para o array de transações.
 */
void free_transactions(char** transactions, int count) {
    if (!transactions) return;
    for (int i = 0; i < count; i++) {
        free(transactions[i]); // Libera cada string de transação
    }
    free(transactions); // Libera o array de ponteiros
}

/**
 * @brief Lê transações de um arquivo, uma por linha.
 *
 * @param filename O nome do arquivo a ser lido.
 * @param num_transactions Ponteiro para int onde o número de transações lidas será armazenado.
 * @return char** Um array de strings (char*) contendo as transações.
 *                NULL em caso de erro ou arquivo vazio. O chamador deve liberar
 *                a memória usando free_transactions().
 */
char** read_transactions(const char* filename, int* num_transactions_out) {
    FILE *infile = NULL;
    char line_buffer[MAX_LINE_LEN];
    int count = 0;
    char **transactions = NULL;
    int capacity = 10; // Capacidade inicial do array dinâmico

    *num_transactions_out = 0; // Inicializa

    infile = fopen(filename, "r");
    if (infile == NULL) {
        perror("Erro ao abrir arquivo para leitura");
        fprintf(stderr, "Arquivo: %s\n", filename);
        return NULL;
    }

    transactions = (char**)malloc(capacity * sizeof(char*));
    if (transactions == NULL) {
        perror("Erro ao alocar memória inicial para transações");
        fclose(infile);
        return NULL;
    }

    while (fgets(line_buffer, sizeof(line_buffer), infile) != NULL) {
        size_t len = strlen(line_buffer);
        // Remove newline no final, se houver
        if (len > 0 && line_buffer[len - 1] == '\n') {
            line_buffer[len - 1] = '\0';
            len--;
        }
        // Ignora linhas vazias
        if (len == 0) {
            continue;
        }

        // Redimensiona o array se necessário
        if (count >= capacity) {
            capacity *= 2;
            char **temp = (char**)realloc(transactions, capacity * sizeof(char*));
            if (temp == NULL) {
                perror("Erro ao realocar memória para transações");
                free_transactions(transactions, count); // Libera o que já foi alocado
                fclose(infile);
                return NULL;
            }
            transactions = temp;
        }

        // Duplica a linha lida e armazena
        transactions[count] = strdup(line_buffer);
        if (transactions[count] == NULL) {
            perror("Erro ao duplicar string de transação (strdup)");
            free_transactions(transactions, count);
            fclose(infile);
            return NULL;
        }
        count++;
    }

    if (ferror(infile)) {
         perror("Erro durante leitura do arquivo");
         free_transactions(transactions, count);
         fclose(infile);
         return NULL;
    }

    fclose(infile);

    if (count == 0) {
        fprintf(stderr, "Nenhuma transação válida encontrada no arquivo '%s'\n", filename);
        free(transactions); // Libera o array vazio
        return NULL;
    }

    // Opcional: Reduzir a capacidade para o tamanho exato usado
    char **final_transactions = (char**)realloc(transactions, count * sizeof(char*));
     if (final_transactions == NULL && count > 0) {
         perror("Erro ao realocar memória final (não crítico, continuando com array maior)");
         // Continua com o array 'transactions' original que ainda é válido
     } else {
        transactions = final_transactions; // Atualiza ponteiro se realloc funcionou ou se count == 0
     }


    *num_transactions_out = count;
    return transactions;
}


FullMerkleTree* build_full_merkle_tree(const char* data_blocks[], int num_blocks) {
    if (num_blocks <= 0) return NULL;

    int max_height_possible = (num_blocks == 1) ? 1 : (int)ceil(log2(num_blocks)) + 1;
    FullMerkleTree* tree = (FullMerkleTree*)malloc(sizeof(FullMerkleTree));
    if (!tree) { perror("malloc FullMerkleTree"); return NULL; }

    tree->all_levels = (char***)malloc(max_height_possible * sizeof(char**));
    tree->nodes_per_level = (int*)malloc(max_height_possible * sizeof(int));
    tree->root_hash = NULL;
    tree->height = 0;
    if (!tree->all_levels || !tree->nodes_per_level) {
        perror("malloc tree arrays");
        free(tree->all_levels); free(tree->nodes_per_level); free(tree);
        return NULL;
    }

    // Nível 0: Folhas
    char** current_level_hashes = (char**)malloc(num_blocks * sizeof(char*));
    if (!current_level_hashes) { /* ... erro ... */ free_full_merkle_tree(tree); return NULL; }
    for(int i=0; i<num_blocks; ++i) current_level_hashes[i] = NULL;

    for (int i = 0; i < num_blocks; i++) {
        current_level_hashes[i] = (char*)malloc(HASH_STR_SIZE);
        if (!current_level_hashes[i] || calculate_sha256_hash_evp(data_blocks[i], NULL, current_level_hashes[i]) != 0) {
            // ... erro, liberar tudo ...
            fprintf(stderr, "Erro hash folha %d\n", i);
            // Liberar hashes já alocados neste nível
            for(int j=0; j<i; ++j) free(current_level_hashes[j]);
            free(current_level_hashes);
            free_full_merkle_tree(tree); // Libera o que foi alocado para a árvore
            return NULL;
        }
    }
    tree->all_levels[tree->height] = current_level_hashes;
    tree->nodes_per_level[tree->height] = num_blocks;
    tree->height++;

    int num_nodes_current_level = num_blocks;

    // Níveis Intermediários
    while (num_nodes_current_level > 1) {
        int num_nodes_next_level = (int)ceil((double)num_nodes_current_level / 2.0);
        char** next_level_hashes = (char**)malloc(num_nodes_next_level * sizeof(char*));
        if (!next_level_hashes) { /* ... erro, liberar tudo ... */ free_full_merkle_tree(tree); return NULL;}
        for(int i=0; i<num_nodes_next_level; ++i) next_level_hashes[i] = NULL;

        for (int i = 0; i < num_nodes_next_level; i++) {
            next_level_hashes[i] = (char*)malloc(HASH_STR_SIZE);
            int left_idx = 2 * i;
            int right_idx = 2 * i + 1;
            const char* left_hash = current_level_hashes[left_idx];
            const char* right_hash = (right_idx < num_nodes_current_level) ? current_level_hashes[right_idx] : left_hash; // Duplica se ímpar

            if (!next_level_hashes[i] || calculate_sha256_hash_evp(left_hash, right_hash, next_level_hashes[i]) != 0) {
                 // ... erro, liberar tudo ...
                fprintf(stderr, "Erro hash nó interno %d nível %d\n", i, tree->height);
                for(int j=0; j<i; ++j) free(next_level_hashes[j]);
                free(next_level_hashes);
                free_full_merkle_tree(tree);
                return NULL;
            }
        }

        // NÃO libera o current_level_hashes aqui, apenas avança
        current_level_hashes = next_level_hashes; // Ponteiro agora aponta para o novo nível
        num_nodes_current_level = num_nodes_next_level;

        // Armazena o nível recém-calculado na árvore
        tree->all_levels[tree->height] = current_level_hashes;
        tree->nodes_per_level[tree->height] = num_nodes_current_level;
        tree->height++;
    }

    // A raiz é o único nó no último nível calculado
    tree->root_hash = (char*)malloc(HASH_STR_SIZE);
     if(!tree->root_hash) { /* erro */ free_full_merkle_tree(tree); return NULL;}
    strcpy(tree->root_hash, tree->all_levels[tree->height - 1][0]);

    return tree;
}


MerkleProof* generate_merkle_proof(int leaf_index, const FullMerkleTree* tree) {
    if (!tree || leaf_index < 0 || leaf_index >= tree->nodes_per_level[0]) {
        return NULL;
    }

    int proof_len = tree->height - 1; // Prova vai do nível 0 até height-2
    if (proof_len <= 0) { // Árvore com 0 ou 1 folha não tem prova
       MerkleProof* proof = (MerkleProof*)calloc(1, sizeof(MerkleProof)); // Retorna prova vazia
       return proof;
    }

    MerkleProof* proof = (MerkleProof*)malloc(sizeof(MerkleProof));
    if (!proof) { perror("malloc proof"); return NULL; }

    proof->sibling_hashes = (char**)malloc(proof_len * sizeof(char*));
    proof->sibling_positions = (int*)malloc(proof_len * sizeof(int));
    proof->proof_length = proof_len;

    if (!proof->sibling_hashes || !proof->sibling_positions) {
        perror("malloc proof arrays");
        free(proof->sibling_hashes); free(proof->sibling_positions); free(proof);
        return NULL;
    }

    int current_node_index = leaf_index;
    for (int level = 0; level < proof_len; ++level) {
        int is_right_node = current_node_index % 2; // 1 se for nó direito, 0 se esquerdo
        int sibling_index = is_right_node ? (current_node_index - 1) : (current_node_index + 1);

        // Verifica se o irmão existe (importante para níveis com nós ímpares)
        if (sibling_index < tree->nodes_per_level[level]) {
            // Aloca e copia o hash do irmão
            proof->sibling_hashes[level] = strdup(tree->all_levels[level][sibling_index]);
             if (!proof->sibling_hashes[level]) {
                 perror("strdup sibling hash");
                 // Liberar o que já foi alocado na prova
                 for (int k=0; k<level; ++k) free(proof->sibling_hashes[k]);
                 free(proof->sibling_hashes); free(proof->sibling_positions); free(proof);
                 return NULL;
             }
            // Define a posição do irmão RELATIVA ao nó atual
            proof->sibling_positions[level] = is_right_node ? 0 : 1; // Se eu sou direito (1), meu irmão é esquerdo (0). Se sou esquerdo (0), meu irmão é direito (1).
        } else {
            // Caso do nó ímpar no final do nível: o "irmão" é ele mesmo.
             proof->sibling_hashes[level] = strdup(tree->all_levels[level][current_node_index]);
              if (!proof->sibling_hashes[level]) { /* ... erro, liberar ... */ return NULL; }
            // A posição aqui é um pouco arbitrária, mas consistente.
            // Se eu sou o último (ímpar), posso me considerar "esquerdo" e meu irmão duplicado "direito".
            proof->sibling_positions[level] = 1;
        }

        // Move para o índice do nó pai no próximo nível
        current_node_index /= 2;
    }

    return proof;
}

int validate_merkle_proof(const char* transaction_data, const MerkleProof* proof, const char* expected_merkle_root) {
    if (!transaction_data || !proof || !expected_merkle_root) return 0; // Inválido

    char current_hash[HASH_STR_SIZE];
    char combined[HASH_STR_SIZE * 2 + 1]; // Espaço para dois hashes + null terminator

    // 1. Calcula o hash inicial da transação
    if (calculate_sha256_hash_evp(transaction_data, NULL, current_hash) != 0) {
        fprintf(stderr, "Erro ao calcular hash inicial na validação.\n");
        return 0; // Falha na validação
    }

    // 2. Itera pela prova, combinando com os irmãos
    for (int i = 0; i < proof->proof_length; ++i) {
        const char* sibling_hash = proof->sibling_hashes[i];
        int sibling_pos = proof->sibling_positions[i];

        // Concatena na ordem correta
        if (sibling_pos == 0) { // Irmão está à esquerda
            snprintf(combined, sizeof(combined), "%s%s", sibling_hash, current_hash);
        } else { // Irmão está à direita (ou é duplicado)
            snprintf(combined, sizeof(combined), "%s%s", current_hash, sibling_hash);
        }

        // Calcula o hash do nível superior
        if (calculate_sha256_hash_evp(combined, NULL, current_hash) != 0) {
             fprintf(stderr, "Erro ao calcular hash no nível %d da validação.\n", i);
             return 0; // Falha na validação
        }
    }

    // 3. Compara o hash calculado final com a raiz esperada
    return strcmp(current_hash, expected_merkle_root) == 0;
}
