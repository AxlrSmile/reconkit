"""Проверка HTTP-заголовков безопасности и флагов cookie."""
import requests

# заголовок -> (серьёзность при отсутствии, рекомендация)
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high", "Добавьте HSTS: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": ("high", "Настройте CSP, чтобы снизить риск XSS"),
    "X-Frame-Options": ("medium", "Используйте DENY или SAMEORIGIN (защита от clickjacking)"),
    "X-Content-Type-Options": ("medium", "Установите nosniff"),
    "Referrer-Policy": ("low", "Например: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("low", "Ограничьте доступ к API браузера (camera, geolocation и т.д.)"),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def check_headers(url: str, timeout: float = 8.0, verify_tls: bool = True) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    resp = requests.get(url, timeout=timeout, verify=verify_tls, allow_redirects=True,
                        headers={"User-Agent": "ReconKit/0.1 (educational)"})
    h = resp.headers
    findings = []

    for name, (severity, advice) in SECURITY_HEADERS.items():
        if name not in h:
            findings.append({"type": "missing_header", "header": name,
                             "severity": severity, "advice": advice})

    for name in LEAKY_HEADERS:
        if name in h:
            findings.append({"type": "info_leak", "header": name, "value": h[name],
                             "severity": "low",
                             "advice": "Скройте версию ПО в ответах сервера"})

    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("SameSite")
        if issues:
            findings.append({"type": "cookie", "header": f"Set-Cookie: {cookie.name}",
                             "severity": "medium",
                             "advice": f"Нет флагов: {', '.join(issues)}"})

    return {"url": resp.url, "status": resp.status_code, "findings": findings}
