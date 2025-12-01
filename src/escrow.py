# src/escrow.py
"""
Módulo para generar clave RSA demo y cifrar la clave maestra para recovery (escrow).
Utiliza PyCryptodome solo para la operación RSA demo.
"""
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

ESCROW_DIR = Path(__file__).resolve().parents[1].parent / "escrow"
ESCROW_DIR.mkdir(parents=True, exist_ok=True)
DEMO_PRIV = ESCROW_DIR / "demo_private.pem"
DEMO_PUB = ESCROW_DIR / "demo_public.pem"
RECOVERY = ESCROW_DIR / "recovery.enc"

def generate_rsa_demo(bits: int = 2048):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    DEMO_PRIV.write_bytes(priv)
    DEMO_PUB.write_bytes(pub)
    return priv, pub

def create_recovery_enc(master_key: bytes, pubkey_pem: bytes = None):
    """
    Cifra master_key con RSA OAEP usando pubkey_pem (si no se provee, usa demo pub).
    Guarda el resultado en escrow/recovery.enc
    """
    if pubkey_pem is None:
        if not DEMO_PUB.exists():
            generate_rsa_demo()
        pubkey_pem = DEMO_PUB.read_bytes()
    rsa_pub = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(rsa_pub)
    enc = cipher.encrypt(master_key)
    RECOVERY.write_bytes(enc)
    return RECOVERY

def decrypt_recovery_enc(private_pem: bytes, enc_blob: bytes) -> bytes:
    rsa_priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(rsa_priv)
    return cipher.decrypt(enc_blob)
