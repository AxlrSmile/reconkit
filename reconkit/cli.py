import argparse
import sys

from . import __version__
from .headers import check_headers
from .ports import parse_ports, scan_ports
from .report import now, save_json, save_markdown
from .subdomains import find_subdomains, load_wordlist

BANNER = f"""ReconKit v{__version__}
[!] Используйте только на системах, на которые у вас есть письменное разрешение
    (свои стенды, HTB/THM, scanme.nmap.org)."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconkit", description="Лёгкий инструмент для разведки")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("ports", help="сканирование TCP-портов")
    sp.add_argument("target")
    sp.add_argument("-p", "--ports", default="top", help="'top', '22,80' или '1-1024'")
    sp.add_argument("-t", "--timeout", type=float, default=1.0)
    sp.add_argument("-w", "--workers", type=int, default=100)
    sp.add_argument("-b", "--banner", action="store_true", help="собирать баннеры")

    sh = sub.add_parser("headers", help="проверка заголовков безопасности")
    sh.add_argument("target", help="URL или домен")
    sh.add_argument("--insecure", action="store_true", help="не проверять TLS-сертификат")

    ss = sub.add_parser("subdomains", help="поиск поддоменов по словарю")
    ss.add_argument("target", help="домен, например example.com")
    ss.add_argument("-W", "--wordlist", default="wordlists/subdomains.txt")
    ss.add_argument("-w", "--workers", type=int, default=50)

    sa = sub.add_parser("all", help="все проверки сразу")
    sa.add_argument("target", help="домен")
    sa.add_argument("-W", "--wordlist", default="wordlists/subdomains.txt")

    for s in (sp, sh, ss, sa):
        s.add_argument("-o", "--output", help="префикс файлов отчёта (создаст .json и .md)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print(BANNER, file=sys.stderr)
    data = {"target": args.target, "timestamp": now()}

    try:
        if args.cmd in ("ports", "all"):
            ports = parse_ports(getattr(args, "ports", "top"))
            data["ports"] = scan_ports(args.target, ports,
                                       getattr(args, "timeout", 1.0),
                                       getattr(args, "workers", 100),
                                       getattr(args, "banner", False))
            print(f"\n[+] Открытые порты ({len(data['ports'])}):")
            for p in data["ports"]:
                print(f"    {p['port']:>5}/tcp  {p['service']:<14} {p['banner']}")

        if args.cmd in ("headers", "all"):
            data["headers"] = check_headers(args.target, verify_tls=not getattr(args, "insecure", False))
            print(f"\n[+] Заголовки: {data['headers']['url']} (HTTP {data['headers']['status']})")
            for f in data["headers"]["findings"]:
                print(f"    [{f['severity'].upper():<6}] {f['header']}: {f['advice']}")

        if args.cmd in ("subdomains", "all"):
            words = load_wordlist(args.wordlist)
            data["subdomains"] = find_subdomains(args.target, words, getattr(args, "workers", 50))
            sd = data["subdomains"]
            if sd["wildcard"]:
                print("\n[!] Wildcard DNS: перебор поддоменов даст ложные результаты")
            else:
                print(f"\n[+] Поддомены ({len(sd['found'])}):")
                for s in sd["found"]:
                    print(f"    {s['subdomain']:<35} {', '.join(s['ips'])}")
    except (OSError, ValueError) as e:
        print(f"[-] Ошибка: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # requests.RequestException и т.п.
        print(f"[-] Ошибка: {e}", file=sys.stderr)
        return 1

    if getattr(args, "output", None):
        save_json(data, args.output + ".json")
        save_markdown(data, args.output + ".md")
        print(f"\n[+] Отчёты: {args.output}.json, {args.output}.md")
    return 0
