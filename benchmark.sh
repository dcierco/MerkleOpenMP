#!/bin/bash

# --- Configuração ---

# Nome do executável C compilado com OpenMP
EXECUTABLE="./merkle_parallel"

# Lista de números de threads para testar
# Modifique esta lista conforme os cores da sua máquina e o que você quer testar.
# Exemplo: Para ir de 1 a 8 núcleos: THREADS=(1 2 3 4 5 6 7 8)
# Exemplo: Potências de 2 até 16: THREADS=(1 2 4 8 16)
# Use 'nproc' (Linux) ou 'sysctl hw.ncpu' (macOS) para ver quantos cores lógicos você tem.
CPU_CORES=$(sysctl -n hw.ncpu) # Comando para macOS
# CPU_CORES=$(nproc) # Comando para Linux
echo "Número de cores lógicos detectados: $CPU_CORES"
# Cria uma sequência de 1 até o número de cores (ou ajuste como preferir)
THREADS=($(seq 1 $CPU_CORES))
# Ou defina manualmente:
# THREADS=(1 2 4 8)

# --- Verificação ---

# Verifica se o executável existe e tem permissão de execução
if [ ! -x "$EXECUTABLE" ]; then
  echo "Erro: Executável '$EXECUTABLE' não encontrado ou sem permissão de execução."
  echo "Certifique-se que compilou o código C com:"
  echo "gcc-14 -fopenmp -I/opt/homebrew/opt/openssl/include merkle_parallel.c -o merkle_parallel -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lm"
  exit 1
fi

# --- Execução do Benchmark ---

echo "============================================="
echo "Iniciando Benchmark para: $EXECUTABLE"
echo "Testando com threads: ${THREADS[@]}" # Mostra a lista de threads que serão usadas
echo "============================================="
echo # Linha em branco

# Loop através de cada número de threads na lista
for T in "${THREADS[@]}"; do
  echo "*** Executando com $T thread(s) ***"

  # Define a variável de ambiente OMP_NUM_THREADS para esta execução específica
  export OMP_NUM_THREADS=$T

  # Executa o programa C. A saída do programa (incluindo a linha de tempo)
  # será impressa diretamente no terminal.
  $EXECUTABLE

  echo # Adiciona uma linha em branco para separação
  echo "---------------------------------------------"
  # sleep 1 # Descomente para adicionar uma pequena pausa entre as execuções, se desejar
done

echo # Linha em branco
echo "============================================="
echo "Benchmark Concluído."
echo "============================================="
