"""TCP-сканер портов с многопоточностью и простым banner grabbing."""
import socket
from concurrent.futures import ThreadPoolExecutor

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Разбирает строку вида '22,80,8000-8100' или 'top'."""
    if spec == "top":
        return TOP_PORTS
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Недопустимые порты: {bad[:5]}")
    return sorted(ports)


def _grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(1.0)
        # Для HTTP-подобных сервисов баннер сам не приходит - отправим запрос
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        return data.decode(errors="ignore").strip().splitlines()[0][:100] if data else ""
    except (OSError, IndexError):
        return ""


def _scan_one(host: str, port: int, timeout: float, banner: bool):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            info = {"port": port, "service": SERVICES.get(port, "unknown"), "banner": ""}
            if banner:
                info["banner"] = _grab_banner(s)
            return info
    except OSError:
        return None


def scan_ports(host: str, ports: list[int], timeout: float = 1.0,
               workers: int = 100, banner: bool = False) -> list[dict]:
    """Возвращает список открытых портов."""
    socket.gethostbyname(host)  # быстрая проверка, что хост резолвится
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: _scan_one(host, p, timeout, banner), ports)
    return sorted((r for r in results if r), key=lambda r: r["port"])
