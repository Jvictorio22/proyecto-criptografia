import matplotlib.pyplot as plt
from pathlib import Path

def test_histogram():
    file = Path("sandbox/out/prueba.txt.enc")
    if not file.exists():
        raise FileNotFoundError("Primero cifra un archivo como prueba.txt.enc")

    data = list(file.read_bytes()) 

    plt.hist(data, bins=range(257))
    plt.title("Histograma de bytes del archivo cifrado")
    plt.xlabel("Byte 0-255")
    plt.ylabel("Frecuencia")

    plt.savefig("histograma_cifrado.png")

