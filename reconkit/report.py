"""Сохранение результатов в JSON и Markdown."""
import json
from datetime import datetime, timezone


def save_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_markdown(data: dict, path: str) -> None:
    L = [f"# ReconKit report: {data['target']}",
         f"_Дата: {data['timestamp']}_\n"]

    if "ports" in data:
        L += ["## Открытые порты", "| Порт | Сервис | Баннер |", "|---|---|---|"]
        L += [f"| {p['port']} | {p['service']} | {p['banner'] or '-'} |" for p in data["ports"]]
        if not data["ports"]:
            L.append("| - | нет открытых портов | - |")
        L.append("")

    if "headers" in data:
        hd = data["headers"]
        L += [f"## Заголовки безопасности ({hd['url']}, HTTP {hd['status']})",
              "| Серьёзность | Проблема | Рекомендация |", "|---|---|---|"]
        L += [f"| {f['severity']} | {f['header']} | {f['advice']} |" for f in hd["findings"]]
        L.append("")

    if "subdomains" in data:
        sd = data["subdomains"]
        L.append("## Поддомены")
        if sd["wildcard"]:
            L.append(f"Обнаружен wildcard DNS ({', '.join(sd['wildcard_ips'])}), перебор бессмысленен.")
        else:
            L += ["| Поддомен | IP |", "|---|---|"]
            L += [f"| {s['subdomain']} | {', '.join(s['ips'])} |" for s in sd["found"]]
        L.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
