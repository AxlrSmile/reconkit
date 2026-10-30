"""Поиск поддоменов перебором по словарю через DNS."""
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor


def _resolve(name: str):
    try:
        return socket.gethostbyname_ex(name)[2]
    except OSError:
        return None


def load_wordlist(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [w.strip() for w in f if w.strip() and not w.startswith("#")]


def find_subdomains(domain: str, words: list[str], workers: int = 50) -> dict:
    # Wildcard DNS: если случайное имя резолвится, результаты будут ложными
    wildcard_ips = _resolve(f"{secrets.token_hex(8)}.{domain}")
    if wildcard_ips:
        return {"wildcard": True, "wildcard_ips": wildcard_ips, "found": []}

    names = [f"{w}.{domain}" for w in words]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        ips = list(pool.map(_resolve, names))
    found = [{"subdomain": n, "ips": i} for n, i in zip(names, ips) if i]
    return {"wildcard": False, "wildcard_ips": [], "found": found}
