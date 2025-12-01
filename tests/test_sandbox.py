# tests/test_sandbox.py
import subprocess
import sys
from pathlib import Path

def test_init_command():
    # Ejecutar init y comprobar que crea sandbox/keys/secret.key
    r = subprocess.run([sys.executable, "-m", "src.cli", "init"], capture_output=True, text=True)
    assert r.returncode == 0 or "Init completado" in r.stdout
    sk = Path.cwd() / "sandbox" / "keys" / "secret.key"
    assert sk.exists()
