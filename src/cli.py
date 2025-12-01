# src/cli.py
import argparse
from pathlib import Path
import secrets
from src.sandbox.sandbox_checker import ensure_sandbox_exists, ensure_in_sandbox
from src.cipher.cipher_core import KEY_SIZE, encrypt_cbc, decrypt_cbc, pad_pkcs7
from src.escrow import generate_rsa_demo, create_recovery_enc
from src.metrics import avalanche_test, shannon_entropy, byte_histogram, time_exec
from src.cipher.cipher_core import encrypt_cbc, decrypt_cbc
import os

REPO_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_KEYS = REPO_ROOT / "sandbox" / "keys"

def _read_bytes_safe(p: Path) -> bytes:
    return p.read_bytes()

def cmd_init(args):
    ensure_sandbox_exists()
    # generar clave maestra 256-bit
    master_key = secrets.token_bytes(KEY_SIZE)
    # guardar en sandbox/keys/secret.key
    SK = SANDBOX_KEYS / "secret.key"
    SK.write_bytes(master_key)
    try:
        SK.chmod(0o600)
    except Exception:
        pass
    # generar RSA demo y crear recovery.enc
    generate_rsa_demo()
    create_recovery_enc(master_key)
    print("Init completado.")
    print(f"Clave maestra escrita en {SK}")
    print("Escrow demo generado en escrow/recovery.enc (demo_private.pem/demo_public.pem en escrow/)")

def cmd_encrypt(args):
    ensure_sandbox_exists()
    infile = ensure_in_sandbox(args.infile)
    outfile = ensure_in_sandbox(args.outfile)
    keyfile = ensure_in_sandbox(args.keyfile)
    key = keyfile.read_bytes()
    iv = secrets.token_bytes(16)
    pt = infile.read_bytes()
    ct = encrypt_cbc(key, pt, iv)
    # formato de salida: IV || ciphertext
    outfile.write_bytes(iv + ct)
    print(f"Cifrado OK -> {outfile}")

def cmd_decrypt(args):
    ensure_sandbox_exists()
    infile = ensure_in_sandbox(args.infile)
    outfile = ensure_in_sandbox(args.outfile)
    keyfile = ensure_in_sandbox(args.keyfile)
    key = keyfile.read_bytes()
    blob = infile.read_bytes()
    if len(blob) < 16:
        print("Archivo cifrado inválido")
        return
    iv = blob[:16]
    ct = blob[16:]
    pt = decrypt_cbc(key, ct, iv)
    outfile.write_bytes(pt)
    print(f"Descifrado OK -> {outfile}")

def cmd_test(args):
    ensure_sandbox_exists()
    keyfile = SANDBOX_KEYS / "secret.key"
    if not keyfile.exists():
        print("No existe secret.key. Ejecuta `init` primero.")
        return
    key = keyfile.read_bytes()
    message_path = ensure_in_sandbox(args.message)
    msg = message_path.read_bytes()
    # funciones de métricas
    def cfn(k,m): return encrypt_cbc(k, m, secrets.token_bytes(16))
    aval = avalanche_test(cfn, key, msg, flips=32)
    ct, t = time_exec(lambda k,m: encrypt_cbc(k,m,secrets.token_bytes(16)), key, msg)
    ent = shannon_entropy(ct)
    hist = byte_histogram(ct)
    print("Avalanche ratios (muestras):", aval)
    print(f"Tiempo cifrado: {t:.6f} s")
    print(f"Entropía del ciphertext: {ent:.4f} bits/byte")
    print("Histograma (primeros 16 bins):", hist[:16])

def main():
    p = argparse.ArgumentParser(prog="cipherx-cli")
    sub = p.add_subparsers(dest="cmd")
    pi = sub.add_parser("init"); pi.set_defaults(func=cmd_init)
    pe = sub.add_parser("encrypt")
    pe.add_argument("--infile", required=True)
    pe.add_argument("--outfile", required=True)
    pe.add_argument("--keyfile", required=True)
    pe.set_defaults(func=cmd_encrypt)
    pd = sub.add_parser("decrypt")
    pd.add_argument("--infile", required=True)
    pd.add_argument("--outfile", required=True)
    pd.add_argument("--keyfile", required=True)
    pd.set_defaults(func=cmd_decrypt)
    pt = sub.add_parser("test")
    pt.add_argument("--message", required=True)
    pt.set_defaults(func=cmd_test)

    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
    else:
        args.func(args)

if __name__ == "__main__":
    main()
