#!/bin/bash

# --- Configuração ---
# Nome do executável PARALELO C compilado com OpenMP
EXECUTABLE="./merkle_validation_parallel"
UTILS_OBJ="merkle_validation_utils.o"   # Arquivo objeto necessário

# Lista de arquivos de dados para testar
DATA_FILES=("data8.txt" "data9.txt" "data800.txt" "data8000.txt" "data80000.txt")

# Lista de números de threads para testar (Ex: 1, 2, 4, 8, 16)
# As threads reais usadas serão limitadas pelo cluster/máquina
# Use os valores solicitados pelo trabalho: 2, 4, 8, 16
# Adicionamos 1 para verificar o overhead do OpenMP vs Sequencial (opcional)
THREADS=(1 2 4 8 16)
# Ou detecte e use:
# CPU_CORES=$(sysctl -n hw.ncpu || nproc 2>/dev/null || echo 4)
# THREADS=($(seq 1 $CPU_CORES)) # Use isto com cuidado, pode exceder 16

# --- Verificações Iniciais ---
# Verifica se o executável existe
if [ ! -x "$EXECUTABLE" ]; then
  echo "ERRO: Executável '$EXECUTABLE' não encontrado ou sem permissão."
  echo "      Compile a versão paralela e as utils primeiro. Ex (Linux):"
  echo "      gcc -Wall -O2 -c merkle_validation_utils.c -o $UTILS_OBJ -lssl -lcrypto -lm" # ATUALIZADO
  echo "      gcc -Wall -O2 -fopenmp merkle_validation_parallel.c $UTILS_OBJ -o $EXECUTABLE -lssl -lcrypto -lm -fopenmp" # ATUALIZADO
  exit 1
fi

# Verifica se o arquivo objeto .o existe (necessário para linkar se recompilar aqui)
if [ ! -f "$UTILS_OBJ" ]; then
  echo "ERRO: Arquivo objeto '$UTILS_OBJ' não encontrado."
  echo "      Compile as utils primeiro. Ex (Linux):"
  echo "      gcc -Wall -O2 -c merkle_validation_utils.c -o $UTILS_OBJ -lssl -lcrypto -lm"
  # exit 1 # Comente se você garante que o executável já está linkado
fi


# Verifica se os arquivos de dados existem
missing_data=0
for datafile in "${DATA_FILES[@]}"; do
  if [ ! -f "$datafile" ]; then
    echo "ERRO: Arquivo de dados '$datafile' não encontrado."
    missing_data=1
  fi
done
if [ $missing_data -eq 1 ]; then
    echo "      Certifique-se que os arquivos .txt estão no diretório atual."
    exit 1
fi

echo "[OK] Executável $EXECUTABLE e arquivos de dados encontrados."
echo "IMPORTANTE: Certifique-se de ter executado ./merkle_validation_sequential <datafile>"
echo "            para CADA arquivo de dados para obter os tempos base SEQUENCIAIS."
echo #

# --- Execução do Benchmark ---
echo "============================================="
echo "Iniciando Benchmark para: $EXECUTABLE"
echo "Arquivos de Teste: ${DATA_FILES[@]}"
echo "Threads por Teste: ${THREADS[@]}"
echo "============================================="

# Loop através de cada ARQUIVO de dados
for datafile in "${DATA_FILES[@]}"; do
  echo # Linha em branco
  echo "#############################################"
  echo "### Testando com Arquivo: $datafile ###"
  echo "#############################################"

  # Loop através de cada NÚMERO de threads
  for T in "${THREADS[@]}"; do
    echo "*** Executando com $T thread(s) ***"
    export OMP_NUM_THREADS=$T

    # Executa o programa C PARALELO passando o nome do arquivo
    # A saída do programa (incluindo a linha de tempo) será impressa.
    "$EXECUTABLE" "$datafile"

    echo # Linha em branco para separação
    echo "---------------------------------------------"
    # sleep 1 # Descomente para pausa entre execuções
  done # Fim do loop de threads

  echo "### Testes paralelos concluídos para: $datafile ###"
  echo "#############################################"

done # Fim do loop de arquivos

echo # Linha em branco
echo "============================================="
echo "Benchmark (Execuções Paralelas) Concluído."
echo "Lembre-se de coletar os tempos da execução SEQUENCIAL separadamente."
echo "============================================="
