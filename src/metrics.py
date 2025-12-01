# src/metrics.py
import math
from collections import Counter
import time

def bit_diff_ratio(b1: bytes, b2: bytes) -> float:
    if len(b1) != len(b2):
        raise ValueError("Los tamaños deben coincidir")
    diff = 0
    for x,y in zip(b1, b2):
        diff += bin(x ^ y).count("1")
    total = len(b1) * 8
    return diff / total

def avalanche_test(cipher_func, key: bytes, message: bytes, flips: int = 16):
    base = cipher_func(key, message)
    results = []
    L = len(message)
    if L == 0:
        return []
    for i in range(flips):
        byte_idx = (i // 8) % L
        bit_idx = i % 8
        m2 = bytearray(message)
        m2[byte_idx] ^= (1 << bit_idx)
        o = cipher_func(key, bytes(m2))
        results.append(bit_diff_ratio(base, o))
    return results

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    l = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / l
        ent -= p * math.log2(p)
    return ent

def byte_histogram(data: bytes):
    counts = Counter(data)
    return [counts.get(i, 0) for i in range(256)]

def time_exec(func, *args, **kwargs):
    t0 = time.perf_counter()
    out = func(*args, **kwargs)
    t1 = time.perf_counter()
    return out, t1 - t0
