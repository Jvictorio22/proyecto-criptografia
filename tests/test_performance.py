import os
import time
from pathlib import Path
import matplotlib.pyplot as plt

def run(cmd):
    return os.system(cmd)

def test_performance():
    sizes = [1024, 100*1024, 1024*1024]  # 1 KB, 100 KB, 1 MB
    labels = ["1 KB", "100 KB", "1 MB"]

    key = "sandbox/keys/key.bin"
    infile = "sandbox/in/perf.txt"
    outfile = "sandbox/out/perf.enc"

    encrypt_times = []
    decrypt_times = []

    for s in sizes:
        Path(infile).write_bytes(os.urandom(s))

        # Cifrado
        t1 = time.time()
        run(f"python -m src.cli encrypt --infile {infile} --outfile {outfile} --keyfile {key}")
        t2 = time.time()

        # Descifrado
        t3 = time.time()
        run(f"python -m src.cli decrypt --infile {outfile} --outfile sandbox/out/perf.dec --keyfile {key}")
        t4 = time.time()

        encrypt_times.append(t2 - t1)
        decrypt_times.append(t4 - t3)


    # Crear tabla de resultados
    fig, ax = plt.subplots(figsize=(7, 2.5))
    ax.axis("off")

    table_data = [
        ["Tamaño", "Cifrado (s)", "Descifrado (s)"],
    ]

    for i in range(len(sizes)):
        table_data.append([
            labels[i],
            f"{encrypt_times[i]:.5f}",
            f"{decrypt_times[i]:.5f}",
        ])

    table = ax.table(
        cellText=table_data,
        cellLoc="center",
        loc="center"
    )

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.6)

    Path("sandbox/out").mkdir(exist_ok=True)
    plt.savefig("sandbox/out/performance_table.png", dpi=300, bbox_inches="tight")
    plt.close()

    assert Path("sandbox/out/performance_table.png").exists()
