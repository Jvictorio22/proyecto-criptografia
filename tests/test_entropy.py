# tests/test_entropy.py
import secrets
from src.cipher.cipher_core import encrypt_cbc, KEY_SIZE
from src.metrics import shannon_entropy

def test_entropy_minimum():
    key = secrets.token_bytes(KEY_SIZE)
    pt = (b"The quick brown fox jumps over the lazy dog. " * 50)
    iv = b'\x00' * 16
    ct = encrypt_cbc(key, pt, iv)
    ent = shannon_entropy(ct)
    assert ent > 1.0  # chequeo básico de sanity
