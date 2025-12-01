# tests/test_avalanche.py
import secrets
from src.cipher.cipher_core import encrypt_cbc, KEY_SIZE
from src.metrics import avalanche_test

def test_avalanche_basic():
    key = secrets.token_bytes(KEY_SIZE)
    msg = b"A" * 128
    def cfn(k,m):
        # usar IV fijo para reproducibilidad en la prueba
        iv = b'\x00' * 16
        return encrypt_cbc(k, m, iv)
    results = avalanche_test(cfn, key, msg, flips=32)
    assert len(results) == 32
    assert all(0.0 < r < 1.0 for r in results)
