#include "merkle_validation_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <arquivo_de_transacoes>\n", argv[0]);
        return 1;
    }
    const char* filename = argv[1];
    int num_transactions = 0;
    char **transactions = NULL;
    FullMerkleTree *tree = NULL;
    MerkleProof **proofs = NULL;
    int validation_errors = 0; // Contador de falhas de validação (não erros de execução)
    int execution_errors = 0; // Contador de erros internos (malloc, hash, etc)

    // --- Pré-computação Sequencial ---
    printf("Lendo transações de '%s'...\n", filename);
    transactions = read_transactions(filename, &num_transactions);
    if (!transactions || num_transactions <= 0) {
        fprintf(stderr, "Falha ao ler transações ou arquivo vazio.\n");
        return 1; // Não pode continuar
    }
    printf("%d transações lidas.\n", num_transactions);

    printf("Construindo a Merkle Tree completa...\n");
    tree = build_full_merkle_tree((const char**)transactions, num_transactions);
    if (!tree) {
        fprintf(stderr, "Falha ao construir a Merkle Tree.\n");
        free_transactions(transactions, num_transactions);
        return 1;
    }
    printf("Merkle Tree construída. Raiz: %s\n", tree->root_hash);

    printf("Gerando %d provas Merkle...\n", num_transactions);
    proofs = (MerkleProof**)malloc(num_transactions * sizeof(MerkleProof*));
    if (!proofs) { perror("malloc proofs array"); execution_errors = 1; goto cleanup; }
    for(int i=0; i<num_transactions; ++i) proofs[i] = NULL; // Inicializa

    for (int i = 0; i < num_transactions; ++i) {
        proofs[i] = generate_merkle_proof(i, tree);
        if (!proofs[i]) {
            fprintf(stderr, "Falha ao gerar prova para transação %d.\n", i);
            execution_errors = 1;
            // Libera provas já geradas antes de sair
            for(int j=0; j<i; ++j) free_merkle_proof(proofs[j]);
            goto cleanup; // Não pode continuar sem todas as provas
        }
    }
    printf("Provas Merkle geradas.\n");
    // --- Fim da Pré-computação ---


    printf("\nIniciando validação PARALELA de %d transações...\n", num_transactions);

    // Variáveis para OpenMP
    double time_spent;
    int local_validation_errors = 0; // Redução para contar erros de validação
    int local_execution_errors = 0;  // Redução para contar erros de execução

    clock_t start = clock();

    for (int i = 0; i < num_transactions; i++) {
        // Não precisamos checar 'execution_errors' aqui, pois se chegamos até aqui,
        // a pré-computação foi bem-sucedida.
        int is_valid = validate_merkle_proof(transactions[i], proofs[i], tree->root_hash);

        if (is_valid == 0) {
            // Poderia ser uma falha de validação legítima ou um erro interno em validate_merkle_proof.
            // A função validate_merkle_proof já imprime stderr em caso de erro interno.
            // Aqui contamos apenas como falha de validação para o resultado final.
            local_validation_errors++;
        }
        // Se validate_merkle_proof retornar < 0 (indicando erro interno), podemos tratar diferente.
        // Mas na implementação atual ela retorna 0 para ambos os casos.
        // Para simplificar, contamos como falha de validação.
    }

    clock_t end = clock();
    time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    // Atualiza contadores globais (já feito pela cláusula reduction)
    validation_errors = local_validation_errors;
    execution_errors = local_execution_errors;

    // --- Resultados ---
    printf("------------------------------------------------------------------\n");
    if (execution_errors > 0) {
         printf("Execução sequencial concluída com ERROS DE EXECUÇÃO.\n");
    } else if (validation_errors > 0) {
         printf("Execução sequencial concluída. %d FALHAS de validação encontradas.\n", validation_errors);
    } else {
         printf("Execução sequencial concluída com SUCESSO. Todas as %d transações são válidas.\n", num_transactions);
    }
    printf("Tempo de execução da validação sequencial: %f segundos\n", time_spent);
    printf("------------------------------------------------------------------\n");


cleanup:
    // --- Limpeza ---
    printf("Limpando memória...\n");
    if (proofs) {
        for (int i = 0; i < num_transactions; ++i) {
             // Só libera se não for NULL (importante se houve erro na geração)
             if(proofs[i]) free_merkle_proof(proofs[i]);
        }
        free(proofs);
    }
    if (tree) {
        free_full_merkle_tree(tree);
    }
    if (transactions) {
        free_transactions(transactions, num_transactions);
    }

    return (execution_errors > 0 || validation_errors > 0); // Retorna 0 se tudo OK
}
