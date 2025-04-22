import matplotlib.pyplot as plt
import numpy as np
import os

# --- Dados Coletados ---

# Threads testadas
threads = np.array([1, 2, 4, 8, 16])

# Tempos Sequenciais (Baseline - de merkle_validation_sequential)
# Organizados por dataset
seq_times = {
    'LAD': {
        'data8': 0.000169,
        'data9': 0.000236, # Mantido, mas não plotado por padrão
        'data800': 0.047151,
        'data8000': 0.592573,
        'data80000': 7.630751,
    },
    'Local': {
        'data8': 0.000106,
        'data9': 0.000078, # Mantido, mas não plotado por padrão
        'data800': 0.013715,
        'data8000': 0.133019,
        'data80000': 1.683377,
    }
}

# Tempos Paralelos (de merkle_validation_parallel com N threads)
# Organizados por dataset, depois máquina, depois array de tempos para [1, 2, 4, 8, 16] threads
par_times = {
    'data8': {
        'LAD': np.array([0.000271, 0.000275, 0.000492, 0.001054, 0.007743]),
        'Local': np.array([0.000168, 0.000176, 0.000190, 0.000268, 0.000292]),
    },
    'data9': {
        'LAD': np.array([0.000288, 0.000260, 0.000360, 0.002875, 0.007632]),
        'Local': np.array([0.000081, 0.000133, 0.000187, 0.000239, 0.000269]),
    },
    'data800': {
        'LAD': np.array([0.048713, 0.024803, 0.025362, 0.013605, 0.013367]),
        'Local': np.array([0.011817, 0.012850, 0.019168, 0.019315, 0.028552]),
    },
    'data8000': {
        'LAD': np.array([0.588384, 0.301056, 0.156985, 0.158873, 0.092196]),
        'Local': np.array([0.135872, 0.165368, 0.254022, 0.342726, 0.387949]),
    },
    'data80000': {
        'LAD': np.array([7.610702, 3.847171, 2.020855, 2.011754, 1.009740]),
        'Local': np.array([1.719926, 2.088032, 3.236972, 4.596705, 5.000432]),
    }
}

# Datasets que queremos plotar
datasets_to_plot = ['data8', 'data800', 'data8000', 'data80000']

# Diretório para salvar os gráficos
output_dir = "graficos"
os.makedirs(output_dir, exist_ok=True)

# --- Geração dos Gráficos ---

for dataset in datasets_to_plot:
    print(f"Gerando gráfico para: {dataset}")

    # Obter tempos sequenciais para o dataset atual
    t_seq_lad = seq_times['LAD'][dataset]
    t_seq_local = seq_times['Local'][dataset]

    # Obter tempos paralelos para o dataset atual
    t_par_lad = par_times[dataset]['LAD']
    t_par_local = par_times[dataset]['Local']

    # Calcular Speedup (Tseq / Tpar)
    speedup_lad = t_seq_lad / np.maximum(t_par_lad, 1e-12)
    speedup_local = t_seq_local / np.maximum(t_par_local, 1e-12)

    # Speedup Ideal
    speedup_ideal = threads

    # --- Plotagem ---
    plt.figure(figsize=(10, 6))
    x_indices = np.arange(len(threads))

    plt.plot(x_indices, speedup_ideal, label='Speedup Ideal (N)', linestyle='--', marker='^', color='black', zorder=1)
    plt.plot(x_indices, speedup_lad, label=f'Speedup Cluster LAD ({dataset})', marker='o', linestyle='-', color='blue', zorder=3)
    plt.plot(x_indices, speedup_local, label=f'Speedup Máquina Local ({dataset})', marker='s', linestyle='-', color='red', zorder=2)

    plt.xticks(x_indices, threads)
    plt.title(f'Speedup da Validação Merkle - {dataset}')
    plt.xlabel('Número de Threads')
    plt.ylabel('Speedup (T_sequencial / T_paralelo)')
    plt.legend()
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Ajustar limites do eixo Y para incluir 0 e o máximo speedup (ideal ou real) + margem
    # REMOVIDA a condição especial para 'data8'
    max_y_all = [np.max(speedup_ideal)]
    # Incluir máximos reais apenas se forem positivos e finitos
    if np.all(np.isfinite(speedup_lad)) and np.max(speedup_lad) > -np.inf:
      max_y_all.append(np.max(speedup_lad))
    if np.all(np.isfinite(speedup_local)) and np.max(speedup_local) > -np.inf:
      max_y_all.append(np.max(speedup_local))

    max_y = np.max(max_y_all)

    plt.ylim(bottom=0)  # Começar sempre em 0
    plt.ylim(top=max_y + 1) # Adicionar uma pequena margem acima do máximo

    # Salvar o gráfico
    output_filename = os.path.join(output_dir, f'speedup_{dataset}.png')
    plt.savefig(output_filename)
    print(f"Gráfico salvo em: {output_filename}")

    plt.close() # Fechar a figura

print("\nProcesso de geração de gráficos concluído.")
