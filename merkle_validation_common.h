#ifndef MERKLE_VALIDATION_COMMON_H
#define MERKLE_VALIDATION_COMMON_H

#include <openssl/evp.h>
#include <openssl/err.h>

#define HASH_BYTES 32
#define HASH_LEN (HASH_BYTES * 2)
#define HASH_STR_SIZE (HASH_LEN + 1)
#define MAX_LINE_LEN 1024

// --- Estruturas ---
typedef struct {
    char **sibling_hashes;
    int *sibling_positions; // 0 = irmão à esquerda, 1 = irmão à direita
    int proof_length;
} MerkleProof;

typedef struct {
    char ***all_levels;   // Array de ponteiros para os níveis (cada nível é char**)
    int *nodes_per_level; // Número de nós em cada nível
    int height;           // Número de níveis (altura da árvore)
    char *root_hash;      // O hash da raiz (string HASH_STR_SIZE)
} FullMerkleTree;

// --- Funções Auxiliares ---
void handle_openssl_errors(void);
int calculate_sha256_hash_evp(const char* input1, const char* input2, char* output_hex);
void free_merkle_proof(MerkleProof* proof);
void free_full_merkle_tree(FullMerkleTree* tree);
void free_transactions(char** transactions, int count);

// --- Funções Principais ---
FullMerkleTree* build_full_merkle_tree(const char* data_blocks[], int num_blocks);
MerkleProof* generate_merkle_proof(int leaf_index, const FullMerkleTree* tree);
int validate_merkle_proof(const char* transaction_data, const MerkleProof* proof, const char* expected_merkle_root);
char** read_transactions(const char* filename, int* num_transactions);

#endif
