# ReconKit

Лёгкий CLI-инструмент на Python для первичной разведки (reconnaissance) при тестировании на проникновение.
Три модуля в одном инструменте: **сканер TCP-портов**, **проверка заголовков безопасности**, **поиск поддоменов**.
Результаты выводятся в консоль и сохраняются в JSON и Markdown.

> ⚠️ **Только для легальных целей.** Используйте инструмент исключительно на системах, которыми вы владеете
> или на тестирование которых получили письменное разрешение (собственная лаборатория, HackTheBox, TryHackMe,
> `scanme.nmap.org`). Автор не несёт ответственности за неправомерное использование.

## Возможности

| Модуль | Что делает |
|---|---|
| `ports` | Многопоточное TCP connect-сканирование, определение сервиса по номеру порта, опциональный banner grabbing |
| `headers` | Проверяет HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; ищет утечки версий (`Server`, `X-Powered-By`); проверяет флаги cookie (Secure, HttpOnly, SameSite) |
| `subdomains` | Перебор по словарю через DNS, автоматическое обнаружение wildcard DNS (защита от ложных срабатываний) |
| отчёты | Флаг `-o name` сохраняет `name.json` и `name.md` |

## Установка

```bash
git clone https://github.com/AxlrSmile/reconkit.git
cd reconkit
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Требуется Python 3.9+.

## Примеры использования

**Сканирование популярных портов с баннерами**
```bash
python reconkit.py ports scanme.nmap.org -b
```
```
[+] Открытые порты (2):
       22/tcp  ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
       80/tcp  http           HTTP/1.1 200 OK
```

**Свой диапазон портов**
```bash
python reconkit.py ports 192.168.56.101 -p 1-1024 -w 200 -t 0.5
python reconkit.py ports 192.168.56.101 -p 22,80,8000-8100
```

**Проверка заголовков безопасности**
```bash
python reconkit.py headers https://example.com
```
```
[+] Заголовки: https://example.com/ (HTTP 200)
    [HIGH  ] Strict-Transport-Security: Добавьте HSTS: max-age=31536000; includeSubDomains
    [HIGH  ] Content-Security-Policy: Настройте CSP, чтобы снизить риск XSS
    [MEDIUM] X-Frame-Options: Используйте DENY или SAMEORIGIN (защита от clickjacking)
```

**Поиск поддоменов со своим словарём**
```bash
python reconkit.py subdomains example.com -W wordlists/subdomains.txt
```

**Всё сразу + отчёт**
```bash
mkdir -p reports
python reconkit.py all example.com -o reports/example
```

## Структура проекта

```
reconkit/
├── reconkit.py            # точка входа
├── reconkit/
│   ├── cli.py             # разбор аргументов, вывод
│   ├── ports.py           # сканер портов
│   ├── headers.py         # проверка заголовков
│   ├── subdomains.py      # перебор поддоменов
│   └── report.py          # JSON / Markdown отчёты
├── wordlists/subdomains.txt
└── requirements.txt
```

## Как это работает

- **Порты:** `socket.create_connection` в пуле потоков (`ThreadPoolExecutor`). Порт считается открытым, если TCP-соединение установлено. Для баннера отправляется `HEAD /` и читается первая строка ответа.
- **Заголовки:** запрос через `requests`, сравнение с набором рекомендуемых заголовков, каждой проблеме присвоена серьёзность и рекомендация.
- **Поддомены:** перед перебором резолвится случайное имя; если оно существует, на домене включён wildcard DNS и перебор пропускается.

## Ограничения и планы

- [ ] Сканирование UDP и SYN-режим (через `scapy`)
- [ ] Пассивный поиск поддоменов (certificate transparency)
- [ ] Определение версий сервисов по сигнатурам
- [ ] HTML-отчёт
- [ ] Юнит-тесты (`pytest`) и GitHub Actions

## Чему я научился

Сетевое программирование на сокетах, многопоточность, как устроены HSTS/CSP, wildcard DNS и т.д. Это важная часть для рекрутера.

## Лицензия

MIT
