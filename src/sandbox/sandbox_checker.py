# src/sandbox/sandbox_checker.py
from pathlib import Path
import sys
import os

# Root sandbox relative to repo root (assume repo root is two levels up from this file)
SANDBOX_ROOT = Path(__file__).resolve().parents[2] / "sandbox"

def ensure_sandbox_exists():
    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    (SANDBOX_ROOT / "in").mkdir(exist_ok=True)
    (SANDBOX_ROOT / "out").mkdir(exist_ok=True)
    (SANDBOX_ROOT / "keys").mkdir(exist_ok=True)

def ensure_in_sandbox(path_like):
    """
    Verifica que la ruta resuelta esté dentro de sandbox. Si no, aborta con código 2.
    path_like: str or Path
    """
    p = Path(path_like)
    # Si es relativo, interpretarlo respecto al cwd
    try:
        p_resolved = p.resolve()
    except Exception:
        p_resolved = (Path.cwd() / p).resolve()
    sandbox_root = SANDBOX_ROOT.resolve()
    if not str(p_resolved).startswith(str(sandbox_root)):
        print(f"[ERROR] Ruta fuera de sandbox detectada: {p_resolved}")
        sys.exit(2)
    return p_resolved

def is_in_sandbox(path_like):
    try:
        p_resolved = Path(path_like).resolve()
    except Exception:
        p_resolved = (Path.cwd() / Path(path_like)).resolve()
    return str(p_resolved).startswith(str(SANDBOX_ROOT.resolve()))
