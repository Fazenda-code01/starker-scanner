# =========================================================
# STARKER Security Scanner v5
# Enterprise Defensive Audit Scanner — Ultra Edition
# Bugs corrigidos + módulos novos + HTML profissional
# =========================================================

import argparse
import csv
import json
import datetime
import re
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import whois

# dnspython é opcional — enriquece análise DNS se disponível
try:
    import dns.resolver as dns_resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# =========================================================
# CONFIG
# =========================================================

VERSION = "5.0"
DEFAULT_TIMEOUT = 12
DEFAULT_WORKERS = 60
UA = f"STARKER-AUDITOR/{VERSION}"

SECURITY_HEADERS = {
    "Content-Security-Policy":      "Protege contra XSS e injeção de conteúdo",
    "X-Content-Type-Options":       "Evita MIME sniffing",
    "X-Frame-Options":              "Protege contra Clickjacking",
    "Strict-Transport-Security":    "Força HTTPS (HSTS)",
    "Referrer-Policy":              "Controla vazamento de referrer",
    "Permissions-Policy":           "Restringe APIs perigosas do browser",
    "Expect-CT":                    "Monitora certificados TLS via CT logs",
    "X-XSS-Protection":            "Protege contra XSS legados",
    "Cross-Origin-Opener-Policy":  "Isola contextos de navegação",
    "Cross-Origin-Resource-Policy":"Controla compartilhamento cross-origin",
    "Cross-Origin-Embedder-Policy":"Habilita isolamento de processos",
}

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "TELNET",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    587:   "SMTP-TLS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle",
    2375:  "Docker",
    2376:  "Docker-TLS",
    3306:  "MySQL",
    3389:  "RDP",
    4200:  "Angular-DEV",
    5000:  "Flask-DEV",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    7001:  "WebLogic",
    8000:  "HTTP-DEV",
    8080:  "HTTP-ALT",
    8443:  "HTTPS-ALT",
    8888:  "Jupyter",
    9000:  "PHP-FPM",
    9090:  "Prometheus",
    9200:  "ElasticSearch",
    9300:  "ElasticSearch-Cluster",
    10000: "Webmin",
    27017: "MongoDB",
    28017: "MongoDB-HTTP",
    50000: "SAP",
}

SENSITIVE_PORTS = {
    21, 22, 23, 25, 389, 445, 1433, 1521, 2375, 2376,
    3306, 3389, 5432, 5900, 6379, 7001, 8888, 9200,
    9300, 10000, 27017, 28017, 50000,
}

SUSPICIOUS_HEADERS = {
    "X-Powered-By":       "expõe tecnologia backend",
    "Server":             "revela versão do servidor web",
    "X-AspNet-Version":   "expõe versão do ASP.NET",
    "X-AspNetMvc-Version":"expõe versão do ASP.NET MVC",
    "X-Generator":        "revela gerador do site",
    "X-Drupal-Cache":     "confirma uso de Drupal",
    "X-Varnish":          "revela uso de Varnish",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "cdn", "static", "assets", "img", "media", "blog",
    "shop", "portal", "app", "mobile", "m", "vpn", "remote",
    "webmail", "autodiscover", "smtp", "pop", "imap", "ns1", "ns2",
    "login", "auth", "oauth", "sso", "cpanel", "phpmyadmin",
]

KNOWN_WAFS = {
    "cloudflare":       "Cloudflare",
    "incapsula":        "Imperva Incapsula",
    "sucuri":           "Sucuri WAF",
    "akamai":           "Akamai",
    "aws-waf":          "AWS WAF",
    "mod_security":     "ModSecurity",
    "barracuda":        "Barracuda WAF",
    "f5":               "F5 BIG-IP",
    "fortiweb":         "FortiWeb",
    "wordfence":        "Wordfence (WordPress)",
}

JS_LIBRARIES = {
    "jquery":       r"jquery[/-]([\d.]+)",
    "react":        r"react[/-]([\d.]+)",
    "angular":      r"angular[/-]([\d.]+)",
    "vue":          r"vue[/-]([\d.]+)",
    "bootstrap":    r"bootstrap[/-]([\d.]+)",
    "lodash":       r"lodash[/-]([\d.]+)",
    "moment":       r"moment[/-]([\d.]+)",
    "axios":        r"axios[/-]([\d.]+)",
    "d3":           r"d3[/-]([\d.]+)",
    "three":        r"three[/-]([\d.]+)",
    "webpack":      r"webpack",
    "babel":        r"babel",
}

# =========================================================
# ESTADO DE AUDITORIA (classe — sem globals sujos)
# =========================================================

class AuditState:
    """Encapsula score e findings. Sem variáveis globais."""

    def __init__(self):
        self.score: int = 100
        self.findings: list[str] = []
        self.start_time: float = time.time()

    def penalize(self, points: int, reason: str):
        self.score -= points
        self.findings.append(f"[-{points}] {reason}")

    def info(self, reason: str):
        self.findings.append(f"[INFO] {reason}")

    def final_score(self) -> int:
        return max(self.score, 0)

    def elapsed(self) -> float:
        return round(time.time() - self.start_time, 2)


# =========================================================
# UTILIDADES
# =========================================================

def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)


def normalize_target(target: str) -> tuple[str, str]:
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"https://{target}"
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("URL inválida")
    host = parsed.netloc.split(":")[0].strip()
    if not host:
        raise ValueError("Domínio inválido")
    return parsed.scheme, host


def banner(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def parse_csp(csp_value: str) -> dict:
    directives = {}
    for part in csp_value.split(";"):
        chunk = part.strip()
        if not chunk:
            continue
        pieces = chunk.split()
        key = pieces[0].lower()
        directives[key] = pieces[1:]
    return directives


def get_set_cookie_headers(response) -> list[str]:
    """Coleta todos os headers Set-Cookie (múltiplos por resposta)."""
    if response is None:
        return []
    # urllib3 raw headers suportam get_all para múltiplos valores
    if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "get_all"):
        cookies = response.raw.headers.get_all("Set-Cookie")
        if cookies:
            return cookies
    # Fallback: header único
    single = response.headers.get("Set-Cookie")
    return [single] if single else []


def get_now_utc() -> datetime.datetime:
    """Compatível com Python 3.12+ (utcnow depreciado)."""
    return datetime.datetime.now(datetime.timezone.utc)


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    return session


def resolve_ips(domain: str) -> list[str]:
    try:
        results = socket.getaddrinfo(domain, None)
        return sorted({item[4][0] for item in results})
    except Exception:
        return []


# =========================================================
# MÓDULO: HTTP
# =========================================================

def analyze_http(domain: str, timeout: int, state: AuditState, verbose: bool) -> requests.Response | None:
    banner("[+] HTTP Analysis")
    session = make_session()
    try:
        response = session.get(f"https://{domain}", timeout=timeout, allow_redirects=True)
        print(f"    Status Code       : {response.status_code}")
        print(f"    URL final         : {response.url}")
        print(f"    Content-Type      : {response.headers.get('Content-Type', 'unknown')}")
        print(f"    Content-Length    : {response.headers.get('Content-Length', 'N/A')} bytes")
        print(f"    Tempo de resposta : {response.elapsed.total_seconds():.3f}s")

        if response.elapsed.total_seconds() > 5:
            state.penalize(3, f"Resposta lenta: {response.elapsed.total_seconds():.1f}s")

        if response.status_code >= 500:
            state.penalize(10, f"Erro do servidor: HTTP {response.status_code}")
        elif response.status_code >= 400:
            state.penalize(5, f"Erro do cliente: HTTP {response.status_code}")

        if verbose:
            print("\n    [VERBOSE] Headers completos recebidos:")
            for k, v in response.headers.items():
                print(f"      {k}: {v}")

        return response
    except requests.exceptions.SSLError as exc:
        print(f"    SSL Error: {exc}")
        state.penalize(20, "Erro SSL/TLS na conexão principal")
        return None
    except requests.exceptions.ConnectionError as exc:
        print(f"    Connection Error: {exc}")
        state.penalize(20, "Site inacessível")
        return None
    except Exception as exc:
        print(f"    HTTP Error: {exc}")
        state.penalize(15, "Falha na requisição HTTP")
        return None


# =========================================================
# MÓDULO: HEADERS DE SEGURANÇA
# =========================================================

def analyze_headers(headers, state: AuditState):
    banner("[+] Security Headers Analysis")
    for header, description in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value:
            print(f"    [OK]      {header}")
            print(f"              └─ {value[:120]}")
            _deep_check_header(header, value, state)
        else:
            print(f"    [MISSING] {header}  ({description})")
            state.penalize(5, f"Header ausente: {header}")


def _deep_check_header(header: str, value: str, state: AuditState):
    """Verificações profundas por header específico."""
    v = value.lower()

    if header == "Strict-Transport-Security":
        if "max-age" not in v:
            state.penalize(5, "HSTS presente sem max-age")
        else:
            try:
                age = int(re.search(r"max-age=(\d+)", v).group(1))
                if age < 15768000:
                    state.penalize(3, f"HSTS max-age muito curto: {age}s (recomendado ≥ 6 meses)")
            except (AttributeError, ValueError):
                pass
        if "includesubdomains" not in v:
            state.penalize(3, "HSTS sem includeSubDomains")
        if "preload" not in v:
            state.penalize(2, "HSTS sem preload")

    elif header == "X-Content-Type-Options":
        if v != "nosniff":
            state.penalize(5, f"X-Content-Type-Options inválido: {value}")

    elif header == "X-Frame-Options":
        if v not in ("deny", "sameorigin"):
            state.penalize(5, f"X-Frame-Options fraco: {value}")

    elif header == "Content-Security-Policy":
        _analyze_csp(value, state)

    elif header == "Referrer-Policy":
        safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin",
                "no-referrer-when-downgrade", "same-origin"}
        if v not in safe:
            state.penalize(3, f"Referrer-Policy potencialmente insegura: {value}")

    elif header == "Permissions-Policy":
        dangerous = ["microphone=*", "camera=*", "geolocation=*", "payment=*"]
        for d in dangerous:
            if d in v:
                state.penalize(5, f"Permissions-Policy permissiva: {d}")


def _analyze_csp(value: str, state: AuditState):
    directives = parse_csp(value)
    if "default-src" not in directives and "script-src" not in directives:
        state.penalize(10, "CSP sem default-src nem script-src")
    unsafe_terms = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]
    for term in unsafe_terms:
        if term in value:
            state.penalize(8, f"CSP insegura: contém {term}")
    if "frame-ancestors" not in directives:
        state.penalize(5, "CSP sem frame-ancestors (clickjacking)")
    if "upgrade-insecure-requests" not in directives:
        state.penalize(3, "CSP sem upgrade-insecure-requests")
    if "*" in value.replace("'none'", ""):
        # wildcard em src values
        if re.search(r"(?:default|script|style|img|font|connect|media|object|frame)-src\s+[^;]*\*", value):
            state.penalize(8, "CSP com wildcard em source directive")


# =========================================================
# MÓDULO: CORS
# =========================================================

def analyze_cors(headers, state: AuditState):
    banner("[+] CORS Policy Analysis")
    origin      = headers.get("Access-Control-Allow-Origin", "")
    credentials = headers.get("Access-Control-Allow-Credentials", "")
    methods     = headers.get("Access-Control-Allow-Methods", "")
    hdrs        = headers.get("Access-Control-Allow-Headers", "")

    if not origin:
        print("    [INFO] Access-Control-Allow-Origin ausente (pode ser intencional)")
        return

    print(f"    Origin     : {origin}")
    print(f"    Credentials: {credentials or 'N/A'}")
    print(f"    Methods    : {methods or 'N/A'}")
    print(f"    Headers    : {hdrs or 'N/A'}")

    is_wildcard = origin.strip() == "*"
    has_creds   = credentials.lower() == "true"

    if is_wildcard and has_creds:
        # BUG ORIGINAL CORRIGIDO: penalizava duplo (-25). Agora -15 único.
        state.penalize(15, "CORS crítico: wildcard + credenciais habilitadas (viola spec CORS)")
    elif is_wildcard:
        state.penalize(5, "CORS amplo: Access-Control-Allow-Origin: *")
    elif has_creds:
        state.penalize(5, "CORS com credenciais — verificar se origin é confiável")

    if methods:
        dangerous_methods = ["DELETE", "PUT", "PATCH", "TRACE", "OPTIONS"]
        for m in dangerous_methods:
            if m in methods.upper():
                state.penalize(3, f"CORS permite método sensível: {m}")
                break


# =========================================================
# MÓDULO: COOKIES
# =========================================================

def analyze_cookies(response, state: AuditState):
    banner("[+] Cookie Security Analysis")
    cookies = get_set_cookie_headers(response)
    if not cookies:
        print("    Nenhum Set-Cookie detectado")
        return

    print(f"    {len(cookies)} cookie(s) detectado(s)")
    for i, cookie in enumerate(cookies, 1):
        lower = cookie.lower()
        name = cookie.split("=")[0].strip() if "=" in cookie else "?"
        print(f"\n    Cookie #{i}: {name}")
        print(f"      Raw: {cookie[:160]}{'...' if len(cookie) > 160 else ''}")

        issues = []
        if "secure" not in lower:
            issues.append("sem Secure")
            state.penalize(5, f"Cookie '{name}' sem atributo Secure")
        if "httponly" not in lower:
            issues.append("sem HttpOnly")
            state.penalize(5, f"Cookie '{name}' sem atributo HttpOnly")
        if "samesite" not in lower:
            issues.append("sem SameSite")
            state.penalize(5, f"Cookie '{name}' sem atributo SameSite")
        elif "samesite=none" in lower and "secure" not in lower:
            issues.append("SameSite=None sem Secure")
            state.penalize(10, f"Cookie '{name}': SameSite=None exige Secure")

        # Cookie de sessão sem expiração explicita pode ser problema
        if "session" in name.lower() and "expires" not in lower and "max-age" not in lower:
            state.info(f"Cookie '{name}' parece de sessão sem expiração explícita")

        if issues:
            print(f"      ⚠ Problemas: {', '.join(issues)}")
        else:
            print("      ✓ Flags de segurança OK")


# =========================================================
# MÓDULO: REDIRECIONAMENTOS
# =========================================================

def analyze_redirects(domain: str, timeout: int, state: AuditState):
    banner("[+] Redirect & Protocol Analysis")
    try:
        response = requests.get(
            f"http://{domain}",
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": UA},
        )
        status   = response.status_code
        location = response.headers.get("Location", "")
        print(f"    HTTP status  : {status}")
        print(f"    Location     : {location or 'N/A'}")

        if status in (301, 302, 307, 308):
            if location.startswith("https://"):
                print("    ✓ Redirecionamento HTTP → HTTPS detectado")
                if status != 301:
                    state.penalize(2, f"Redirecionamento HTTP usa {status} em vez de 301 (permanente)")
            else:
                state.penalize(10, "Redirecionamento HTTP não leva para HTTPS")
        elif status == 200:
            state.penalize(15, "HTTP responde 200 direto sem redirecionar para HTTPS")
        else:
            state.penalize(5, f"Status HTTP inesperado: {status}")

    except Exception as exc:
        print(f"    Redirect check error: {exc}")
        state.penalize(5, "Falha na verificação de redirecionamento HTTP")


# =========================================================
# MÓDULO: SSL / TLS
# =========================================================

def analyze_ssl(domain: str, timeout: int, state: AuditState) -> dict:
    banner("[+] SSL/TLS Analysis")
    result = {}

    # --- Probe de versões suportadas (BUG CORRIGIDO: TLSv1/1.1 removidos Python 3.10+) ---
    protocol_tests = [("TLSv1.3", "TLSv1_3"), ("TLSv1.2", "TLSv1_2"),
                      ("TLSv1.1", "TLSv1_1"), ("TLSv1", "TLSv1")]
    supported = []
    for name, attr in protocol_tests:
        version = getattr(ssl.TLSVersion, attr, None)
        if version is None:
            continue  # Não disponível neste Python/OpenSSL
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported.append(name)
        except Exception:
            pass

    print(f"    Protocolos suportados: {', '.join(supported) or 'Nenhum detectado'}")
    result["supported_protocols"] = supported

    if any(v in supported for v in ["TLSv1", "TLSv1.1"]):
        state.penalize(15, "Protocolo TLS legado habilitado (TLS 1.0/1.1)")
    if "TLSv1.3" not in supported:
        state.penalize(5, "TLS 1.3 não suportado")
    if "TLSv1.2" not in supported and "TLSv1.3" not in supported:
        state.penalize(20, "Nenhum protocolo TLS moderno disponível")

    # --- Análise do certificado ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert   = ssock.getpeercert()
                ver    = ssock.version()
                cipher = ssock.cipher()

                print(f"    TLS version   : {ver}")
                print(f"    Cipher suite  : {cipher[0] if cipher else 'unknown'}")

                result["tls_version"] = ver
                result["cipher"] = cipher[0] if cipher else None

                if ver and ver not in ("TLSv1.2", "TLSv1.3"):
                    state.penalize(15, f"Protocolo TLS fraco em uso: {ver}")

                if cipher:
                    weak = ["rc4", "des", "3des", "null", "exp", "anon", "md5"]
                    if any(w in cipher[0].lower() for w in weak):
                        state.penalize(10, f"Cifra fraca detectada: {cipher[0]}")

                issuer  = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                expire  = cert.get("notAfter")
                issued  = cert.get("notBefore")

                org = issuer.get("organizationName") or issuer.get("O", "N/A")
                cn  = subject.get("commonName", "N/A")

                print(f"    Issuer        : {org}")
                print(f"    Common Name   : {cn}")
                print(f"    Emissão       : {issued}")
                print(f"    Expiração     : {expire}")

                result.update({"issuer": org, "common_name": cn,
                               "not_before": issued, "not_after": expire})

                if expire:
                    try:
                        exp_dt = datetime.datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z")
                        exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
                        days   = (exp_dt - get_now_utc()).days
                        print(f"    Validade      : {days} dias restantes")
                        result["days_until_expiry"] = days
                        if days < 0:
                            state.penalize(30, "Certificado SSL expirado!")
                        elif days < 7:
                            state.penalize(20, f"Certificado expira em {days} dias — urgente!")
                        elif days < 30:
                            state.penalize(10, f"Certificado expira em {days} dias")
                        elif days < 60:
                            state.penalize(5, f"Certificado expira em breve: {days} dias")
                    except ValueError:
                        pass

                sans = cert.get("subjectAltName", [])
                if sans:
                    san_vals = [val for _, val in sans]
                    print(f"    SANs          : {', '.join(san_vals[:8])}"
                          f"{'...' if len(san_vals) > 8 else ''}")
                    result["sans"] = san_vals

                    # Verificar se o domínio está nos SANs
                    domain_covered = any(
                        domain == v or (v.startswith("*.") and domain.endswith(v[1:]))
                        for v in san_vals
                    )
                    if not domain_covered:
                        state.penalize(10, f"Domínio '{domain}' não coberto pelos SANs do certificado")

                # Self-signed check
                if issuer == subject:
                    state.penalize(20, "Certificado auto-assinado detectado")

    except ssl.SSLCertVerificationError as exc:
        print(f"    SSL Cert Error: {exc}")
        state.penalize(20, f"Falha de verificação do certificado: {exc}")
    except Exception as exc:
        print(f"    SSL Error: {exc}")
        state.penalize(15, "Falha na análise SSL/TLS")

    return result


# =========================================================
# MÓDULO: DNS
# =========================================================

def analyze_dns(domain: str, state: AuditState) -> dict:
    banner("[+] DNS Analysis")
    result = {"ips": [], "ipv6": [], "spf": None, "dmarc": None,
              "mx": [], "dnssec": False, "ns": []}

    # IPs (A/AAAA via socket)
    try:
        infos = socket.getaddrinfo(domain, None)
        ipv4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        ipv6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        result["ips"]  = ipv4
        result["ipv6"] = ipv6
        print(f"    IPv4: {', '.join(ipv4) or 'N/A'}")
        print(f"    IPv6: {', '.join(ipv6) or 'N/A'}")
        if not ipv4 and not ipv6:
            state.penalize(10, "Domínio não resolve")
    except Exception as exc:
        print(f"    DNS resolve error: {exc}")
        state.penalize(10, "Falha DNS na resolução de IPs")

    # Registros avançados via dnspython (SPF, DMARC, MX, NS)
    if HAS_DNSPYTHON:
        _analyze_dns_records_dnspython(domain, result, state)
    else:
        print("    [INFO] dnspython não instalado — SPF/DMARC/MX não verificados")
        print("           Execute: pip install dnspython")
        state.info("dnspython ausente — análise DNS limitada")

    return result


def _analyze_dns_records_dnspython(domain: str, result: dict, state: AuditState):
    resolver = dns_resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 10

    # SPF
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                result["spf"] = txt
                print(f"    SPF  : {txt[:100]}")
                if "~all" in txt:
                    state.penalize(3, "SPF usa ~all (softfail) em vez de -all (fail)")
                elif "+all" in txt:
                    state.penalize(15, "SPF crítico: +all permite qualquer servidor enviar e-mail")
                elif "-all" in txt:
                    print("    ✓ SPF com -all (configuração correta)")
                break
        if not result["spf"]:
            state.penalize(5, "SPF ausente — domínio vulnerável a e-mail spoofing")
            print("    SPF  : [AUSENTE]")
    except Exception:
        print("    SPF  : [erro na consulta]")

    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=DMARC1" in txt:
                result["dmarc"] = txt
                print(f"    DMARC: {txt[:100]}")
                if "p=none" in txt:
                    state.penalize(5, "DMARC com p=none (apenas monitoramento, sem bloqueio)")
                elif "p=quarantine" in txt:
                    print("    ✓ DMARC com p=quarantine")
                elif "p=reject" in txt:
                    print("    ✓ DMARC com p=reject (configuração mais segura)")
                break
        if not result["dmarc"]:
            state.penalize(5, "DMARC ausente")
            print("    DMARC: [AUSENTE]")
    except Exception:
        state.penalize(5, "DMARC ausente ou inacessível")
        print("    DMARC: [AUSENTE]")

    # MX
    try:
        answers = resolver.resolve(domain, "MX")
        mxs = sorted([(r.preference, str(r.exchange)) for r in answers])
        result["mx"] = [f"{pref} {host}" for pref, host in mxs]
        print(f"    MX   : {', '.join(result['mx'][:3])}")
    except Exception:
        print("    MX   : [não encontrado]")

    # NS
    try:
        answers = resolver.resolve(domain, "NS")
        nss = sorted([str(r) for r in answers])
        result["ns"] = nss
        print(f"    NS   : {', '.join(nss[:4])}")
    except Exception:
        print("    NS   : [não encontrado]")

    # DNSSEC (verifica presença de RRSIG)
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        if answers:
            result["dnssec"] = True
            print("    ✓ DNSSEC habilitado")
    except Exception:
        print("    DNSSEC: não detectado")
        state.info("DNSSEC não habilitado (não crítico, mas recomendado)")


# =========================================================
# MÓDULO: SCAN DE PORTAS
# =========================================================

def _scan_port(ip: str, port: int, service: str, timeout: float) -> tuple | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return port, service, ip
    except Exception:
        pass
    return None


def scan_ports(ips: list[str], workers: int, timeout: float, state: AuditState) -> list[dict]:
    banner("[+] Port Exposure Analysis")
    if not ips:
        print("    Sem IPs para scan de portas")
        return []

    # BUG CORRIGIDO: varrer todos os IPs (não só o primeiro)
    # Limitado aos primeiros 3 para evitar timeout excessivo
    scan_ips = ips[:3]
    print(f"    Varrendo {len(COMMON_PORTS)} portas em {len(scan_ips)} IP(s)...")

    tasks = [
        (ip, port, service)
        for ip in scan_ips
        for port, service in COMMON_PORTS.items()
    ]

    open_ports_raw = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_port, ip, port, service, timeout): (ip, port)
            for ip, port, service in tasks
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports_raw.append(result)

    # Deduplica por porta (pode aparecer em múltiplos IPs)
    seen_ports: set[int] = set()
    open_ports: list[dict] = []
    for port, service, ip in sorted(open_ports_raw, key=lambda x: x[0]):
        if port not in seen_ports:
            seen_ports.add(port)
            open_ports.append({"port": port, "service": service, "ip": ip})

    if not open_ports:
        print("    Nenhuma porta comum aberta detectada")
        return []

    print(f"\n    {len(open_ports)} porta(s) abertas:")
    for p in open_ports:
        flag = "⚠" if p["port"] in SENSITIVE_PORTS else "○"
        print(f"    {flag} {p['port']:>5}  {p['service']:<20} ({p['ip']})")
        if p["port"] in SENSITIVE_PORTS:
            state.penalize(5, f"Porta sensível exposta: {p['port']} ({p['service']})")

    if len(open_ports) > 6:
        state.penalize(5, f"Superfície de ataque ampla: {len(open_ports)} portas abertas")

    return open_ports


# =========================================================
# MÓDULO: WAF DETECTION
# =========================================================

def detect_waf(response, state: AuditState) -> str | None:
    banner("[+] WAF / CDN Detection")
    if response is None:
        print("    Sem resposta para analisar")
        return None

    headers_str = " ".join(
        f"{k.lower()} {v.lower()}"
        for k, v in response.headers.items()
    ).lower()

    detected = None
    for signature, name in KNOWN_WAFS.items():
        if signature in headers_str:
            detected = name
            break

    # Headers específicos de WAF/CDN
    waf_headers = {
        "cf-ray":           "Cloudflare",
        "x-sucuri-id":      "Sucuri",
        "x-fw-hash":        "Fastly",
        "x-cache":          "CDN (genérico)",
        "x-amz-cf-id":      "AWS CloudFront",
        "x-akamai-transformed": "Akamai",
        "x-cdn":            "CDN (genérico)",
        "x-edge-ip":        "Edge CDN",
    }
    for hdr, name in waf_headers.items():
        if hdr in {k.lower() for k in response.headers}:
            detected = detected or name
            break

    if detected:
        print(f"    ✓ Detectado: {detected}")
        state.info(f"WAF/CDN em uso: {detected}")
    else:
        print("    Nenhum WAF/CDN detectado nos headers")
        state.penalize(5, "Nenhum WAF ou CDN detectado — site potencialmente desprotegido")

    return detected


# =========================================================
# MÓDULO: TECHNOLOGY FINGERPRINT
# =========================================================

def fingerprint_technology(headers, response, state: AuditState) -> dict:
    banner("[+] Technology Fingerprint")
    found = {}

    # Headers suspeitos
    for header, risk in SUSPICIOUS_HEADERS.items():
        value = headers.get(header)
        if value:
            print(f"    ⚠ {header}: {value}  ({risk})")
            state.penalize(2, f"Tecnologia exposta via {header}: {value}")
            found[header] = value

    # JS libraries no HTML
    if response is not None:
        try:
            body = response.text[:50000]  # primeiros 50KB
            print("\n    Bibliotecas JS detectadas:")
            libs_found = False
            for lib, pattern in JS_LIBRARIES.items():
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else "detectado"
                    print(f"      {lib}: {version}")
                    found[f"js_{lib}"] = version
                    libs_found = True
            if not libs_found:
                print("      Nenhuma biblioteca comum detectada")
        except Exception:
            pass

    # HTTP/2 check
    try:
        if hasattr(response, "raw") and hasattr(response.raw, "version"):
            proto_ver = response.raw.version
            if proto_ver == 20:
                print("\n    ✓ HTTP/2 em uso")
                found["http_version"] = "HTTP/2"
            elif proto_ver == 11:
                print("\n    ⚠ HTTP/1.1 (sem HTTP/2)")
                found["http_version"] = "HTTP/1.1"
                state.penalize(2, "HTTP/2 não habilitado")
    except Exception:
        pass

    return found


# =========================================================
# MÓDULO: SECURITY.TXT
# =========================================================

def check_security_txt(domain: str, timeout: int, state: AuditState) -> dict | None:
    banner("[+] Security.txt Check (RFC 9116)")
    paths = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
    ]
    session = make_session()
    for url in paths:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and "contact" in r.text.lower():
                print(f"    ✓ security.txt encontrado em {url}")
                data = {"url": url}

                # Extrai campos principais
                for field in ["Contact", "Expires", "Encryption", "Policy", "Acknowledgments"]:
                    match = re.search(rf"^{field}:\s*(.+)$", r.text, re.MULTILINE | re.IGNORECASE)
                    if match:
                        print(f"      {field}: {match.group(1).strip()}")
                        data[field.lower()] = match.group(1).strip()

                # Verificar expiração
                if "expires" in data:
                    try:
                        exp = datetime.datetime.fromisoformat(data["expires"].rstrip("Z"))
                        exp = exp.replace(tzinfo=datetime.timezone.utc)
                        if exp < get_now_utc():
                            state.penalize(3, "security.txt expirado")
                            print("      ⚠ security.txt expirado!")
                    except ValueError:
                        pass

                state.info("security.txt presente (boas práticas de disclosure)")
                return data
        except Exception:
            pass

    print("    security.txt não encontrado")
    state.penalize(2, "security.txt ausente (RFC 9116)")
    return None


# =========================================================
# MÓDULO: ROBOTS.TXT / SITEMAP
# =========================================================

def check_robots_txt(domain: str, timeout: int, state: AuditState) -> dict:
    banner("[+] Robots.txt & Sitemap Analysis")
    result = {}
    session = make_session()

    try:
        r = session.get(f"https://{domain}/robots.txt", timeout=timeout)
        if r.status_code == 200:
            print(f"    ✓ robots.txt encontrado ({len(r.text)} bytes)")
            lines = r.text.splitlines()

            # Detectar caminhos sensíveis expostos em Disallow
            sensitive_paths = [
                "/admin", "/wp-admin", "/phpmyadmin", "/backup", "/config",
                "/database", "/.env", "/api", "/private", "/secret",
            ]
            exposed = []
            for line in lines:
                line_lower = line.lower()
                if line_lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    for sp in sensitive_paths:
                        if sp in path.lower():
                            exposed.append(path)
                            break

            if exposed:
                print(f"    ⚠ Caminhos sensíveis expostos no robots.txt:")
                for p in exposed[:10]:
                    print(f"      {p}")
                state.penalize(5, f"robots.txt expõe {len(exposed)} caminho(s) sensível(is)")

            # Sitemap
            sitemap_line = next(
                (l for l in lines if l.lower().startswith("sitemap:")), None
            )
            if sitemap_line:
                sitemap_url = sitemap_line.split(":", 1)[1].strip()
                print(f"    Sitemap: {sitemap_url}")
                result["sitemap"] = sitemap_url

            result["exposed_paths"] = exposed
            result["present"] = True
        else:
            print(f"    robots.txt retornou HTTP {r.status_code}")
            result["present"] = False
    except Exception as exc:
        print(f"    robots.txt error: {exc}")
        result["present"] = False

    return result


# =========================================================
# MÓDULO: HTTP METHODS
# =========================================================

def check_http_methods(domain: str, timeout: int, state: AuditState) -> list[str]:
    banner("[+] HTTP Methods (OPTIONS)")
    session = make_session()
    dangerous = []
    try:
        r = session.options(f"https://{domain}", timeout=timeout)
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
        if allow:
            print(f"    Allow: {allow}")
            dangerous_methods = ["TRACE", "TRACK", "DELETE", "PUT", "CONNECT"]
            for m in dangerous_methods:
                if m in allow.upper():
                    dangerous.append(m)
            if dangerous:
                state.penalize(5, f"Métodos HTTP perigosos habilitados: {', '.join(dangerous)}")
                print(f"    ⚠ Métodos perigosos: {', '.join(dangerous)}")
            else:
                print("    ✓ Nenhum método perigoso detectado")
        else:
            print("    Header Allow não retornado")
    except Exception as exc:
        print(f"    OPTIONS error: {exc}")
    return dangerous


# =========================================================
# MÓDULO: SUBDOMAIN ENUMERATION
# =========================================================

def enumerate_subdomains(domain: str, state: AuditState) -> list[str]:
    banner("[+] Subdomain Enumeration")
    base = ".".join(domain.split(".")[-2:])  # domínio base sem www etc.
    found = []
    print(f"    Testando {len(COMMON_SUBDOMAINS)} subdomínios comuns...")

    def check_sub(sub: str) -> str | None:
        target = f"{sub}.{base}"
        try:
            socket.setdefaulttimeout(2)
            socket.getaddrinfo(target, None)
            return target
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_sub, s): s for s in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort()
    if found:
        print(f"    {len(found)} subdomínio(s) encontrado(s):")
        for sub in found[:20]:
            print(f"      {sub}")
        if len(found) > 20:
            print(f"      ... e mais {len(found) - 20}")
        state.info(f"Subdomínios ativos: {len(found)}")
    else:
        print("    Nenhum subdomínio comum encontrado")

    return found


# =========================================================
# MÓDULO: WHOIS
# =========================================================

def analyze_whois(domain: str, state: AuditState) -> dict:
    banner("[+] WHOIS Analysis")
    try:
        data = whois.whois(domain)

        registrar = str(data.registrar) if data.registrar else "N/A"
        created   = str(data.creation_date)
        expires   = str(data.expiration_date)
        updated   = str(getattr(data, "updated_date", "N/A"))
        org       = str(getattr(data, "org", "N/A"))
        country   = str(getattr(data, "country", "N/A"))

        print(f"    Registrar     : {registrar}")
        print(f"    Organização   : {org}")
        print(f"    País          : {country}")
        print(f"    Criação       : {created}")
        print(f"    Atualização   : {updated}")
        print(f"    Expiração     : {expires}")

        if not data.registrar:
            state.penalize(5, "WHOIS incompleto — registrar não retornado")

        # Verificar se domínio expira em breve
        raw_exp = data.expiration_date
        if isinstance(raw_exp, list):
            raw_exp = raw_exp[0]
        if isinstance(raw_exp, datetime.datetime):
            if raw_exp.tzinfo is None:
                raw_exp = raw_exp.replace(tzinfo=datetime.timezone.utc)
            days = (raw_exp - get_now_utc()).days
            if days < 30:
                state.penalize(10, f"Domínio expira em {days} dias!")
                print(f"    ⚠ Domínio expira em {days} dias!")
            elif days < 90:
                state.penalize(3, f"Domínio expira em {days} dias")

        return {
            "registrar": registrar,
            "org": org,
            "country": country,
            "creation_date": created,
            "updated_date": updated,
            "expiration_date": expires,
        }
    except Exception as exc:
        print(f"    WHOIS Error: {exc}")
        state.penalize(5, "Falha ao obter WHOIS")
        return {}


# =========================================================
# ORQUESTRADOR
# =========================================================

def run_audit(domain: str, timeout: int, workers: int,
              skip_whois: bool, skip_ports: bool, skip_subdomains: bool,
              verbose: bool) -> tuple[AuditState, dict]:

    state = AuditState()

    # HTTP (retorna response para reuso)
    response = analyze_http(domain, timeout, state, verbose)

    headers = response.headers if response else {}

    # Headers de segurança
    if headers:
        analyze_headers(headers, state)
        analyze_cors(headers, state)

    # Cookies
    analyze_cookie_flags = analyze_cookies  # alias por clareza
    analyze_cookie_flags(response, state)

    # Redirecionamentos
    analyze_redirects(domain, timeout, state)

    # SSL/TLS
    ssl_data = analyze_ssl(domain, timeout, state)

    # DNS
    dns_data = analyze_dns(domain, state)
    ips = dns_data.get("ips", [])

    # Portas
    open_ports = []
    if not skip_ports:
        open_ports = scan_ports(ips, workers, timeout=1.5, state=state)

    # WAF
    waf = detect_waf(response, state)

    # Fingerprint
    tech = fingerprint_technology(headers, response, state)

    # Security.txt
    sectxt = check_security_txt(domain, timeout, state)

    # Robots.txt
    robots = check_robots_txt(domain, timeout, state)

    # HTTP Methods
    methods = check_http_methods(domain, timeout, state)

    # Subdomínios
    subdomains = []
    if not skip_subdomains:
        subdomains = enumerate_subdomains(domain, state)

    # WHOIS
    whois_data = {}
    if not skip_whois:
        whois_data = analyze_whois(domain, state)

    target_data = {
        "url":         f"https://{domain}",
        "final_url":   response.url if response else None,
        "headers":     dict(headers),
        "ips":         ips,
        "ipv6":        dns_data.get("ipv6", []),
        "dns":         dns_data,
        "ssl":         ssl_data,
        "open_ports":  open_ports,
        "waf":         waf,
        "technology":  tech,
        "security_txt":sectxt,
        "robots":      robots,
        "http_methods":methods,
        "subdomains":  subdomains,
        "whois":       whois_data,
        "elapsed":     state.elapsed(),
    }
    return state, target_data


# =========================================================
# RELATÓRIO: UTILITÁRIOS
# =========================================================

def get_risk_level(s: int) -> str:
    if s >= 90: return "LOW"
    if s >= 70: return "MODERATE"
    if s >= 50: return "HIGH"
    return "CRITICAL"


def get_risk_color(level: str) -> str:
    return {"LOW": "#22c55e", "MODERATE": "#f59e0b",
            "HIGH": "#f97316", "CRITICAL": "#ef4444"}.get(level, "#94a3b8")


def determine_output_path(domain: str, output: str | None, fmt: str) -> Path:
    if output:
        p = Path(output)
        return p.with_suffix(f".{fmt}") if p.suffix == "" else p
    return Path(f"starker_report_{safe_filename(domain)}.{fmt}")


# =========================================================
# RELATÓRIO: HTML (profissional, dark mode, responsivo)
# =========================================================

def generate_html_report(domain: str, report: dict, output_path: Path):
    score     = report["score"]
    risk      = report["risk_level"]
    color     = get_risk_color(risk)
    details   = report["details"]
    findings  = report["findings"]
    generated = report["generated_at"]

    def row(label, value):
        return f"<tr><td class='label'>{label}</td><td>{value or '—'}</td></tr>"

    # Findings separados em penalidades e infos
    penalties = [f for f in findings if f.startswith("[-")]
    infos     = [f for f in findings if f.startswith("[INFO]")]

    findings_html = "".join(
        f"<li class='{'info' if f.startswith('[INFO]') else 'penalty'}'>{f}</li>"
        for f in findings
    )

    ports_html = "".join(
        f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['ip']}</td>"
        f"<td class='{'danger' if p['port'] in SENSITIVE_PORTS else 'ok'}'>{'⚠ Sensível' if p['port'] in SENSITIVE_PORTS else '○ Normal'}</td></tr>"
        for p in details.get("open_ports", [])
    )

    headers_html = "".join(
        f"<tr><td>{k}</td><td class='mono'>{v[:120]}</td></tr>"
        for k, v in details.get("headers", {}).items()
    )

    subdomains_html = "".join(
        f"<li>{s}</li>" for s in details.get("subdomains", [])
    )

    ssl = details.get("ssl", {})
    dns = details.get("dns", {})
    whois_d = details.get("whois", {})

    gauge_deg = int((score / 100) * 180)

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STARKER Report — {domain}</title>
<style>
  :root {{
    --bg: #0f172a; --bg2: #1e293b; --bg3: #334155;
    --text: #e2e8f0; --text2: #94a3b8; --text3: #64748b;
    --accent: #6366f1; --border: #334155;
    --ok: #22c55e; --warn: #f59e0b; --danger: #ef4444;
    --risk: {color};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
         color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }}
  header {{ text-align: center; margin-bottom: 2.5rem; }}
  header h1 {{ font-size: 1.8rem; color: var(--accent); letter-spacing: .5px; }}
  header p {{ color: var(--text2); margin-top: .4rem; font-size: .9rem; }}
  .hero {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .score-card {{ background: var(--bg2); border: 1px solid var(--border);
                 border-radius: 16px; padding: 2rem; flex: 1; min-width: 260px;
                 text-align: center; }}
  .gauge-wrap {{ position: relative; width: 160px; height: 90px; margin: 0 auto 1rem; overflow: hidden; }}
  .gauge-bg {{ width: 160px; height: 80px; border-radius: 80px 80px 0 0;
               background: conic-gradient(var(--bg3) 0deg 180deg); }}
  .gauge-fill {{ position: absolute; top: 0; left: 0; width: 160px; height: 80px;
                 border-radius: 80px 80px 0 0;
                 background: conic-gradient(var(--risk) 0deg {gauge_deg}deg, transparent {gauge_deg}deg 180deg);
                 transform-origin: center bottom; }}
  .score-num {{ font-size: 3rem; font-weight: 700; color: var(--risk); line-height: 1; }}
  .score-label {{ color: var(--text2); font-size: .85rem; margin-top: .3rem; }}
  .risk-badge {{ display: inline-block; background: var(--risk); color: #000;
                 padding: .3rem 1rem; border-radius: 20px; font-weight: 700;
                 font-size: .9rem; margin-top: .7rem; }}
  .meta-card {{ background: var(--bg2); border: 1px solid var(--border);
                border-radius: 16px; padding: 1.5rem; flex: 2; min-width: 300px; }}
  .meta-card h3 {{ font-size: 1rem; color: var(--accent); margin-bottom: 1rem; }}
  .meta-grid {{ display: grid; grid-template-columns: auto 1fr; gap: .4rem 1rem; }}
  .meta-grid .k {{ color: var(--text2); font-size: .85rem; white-space: nowrap; }}
  .meta-grid .v {{ font-size: .85rem; word-break: break-all; }}
  .section {{ background: var(--bg2); border: 1px solid var(--border);
              border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .section h2 {{ font-size: 1rem; color: var(--accent); margin-bottom: 1rem;
                 display: flex; align-items: center; gap: .5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .84rem; }}
  th {{ background: var(--bg3); color: var(--text2); padding: .6rem .8rem;
        text-align: left; font-weight: 600; }}
  td {{ padding: .5rem .8rem; border-top: 1px solid var(--border);
        vertical-align: top; word-break: break-word; }}
  td.label {{ color: var(--text2); white-space: nowrap; width: 160px; }}
  td.mono {{ font-family: monospace; font-size: .78rem; }}
  td.ok {{ color: var(--ok); }}
  td.danger {{ color: var(--danger); }}
  ul.findings {{ list-style: none; }}
  ul.findings li {{ padding: .4rem .7rem; border-radius: 6px; font-size: .84rem;
                    margin-bottom: .3rem; font-family: monospace; }}
  ul.findings li.penalty {{ background: rgba(239,68,68,.12); color: #fca5a5; }}
  ul.findings li.info {{ background: rgba(99,102,241,.1); color: #a5b4fc; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: .5rem; }}
  .stat {{ background: var(--bg3); border-radius: 10px; padding: .6rem 1.2rem;
           font-size: .85rem; text-align: center; flex: 1; min-width: 100px; }}
  .stat .n {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); }}
  ul.sub-list {{ columns: 2; list-style: none; font-size: .84rem; }}
  ul.sub-list li {{ padding: .15rem 0; color: var(--text2); }}
  ul.sub-list li::before {{ content: '→ '; color: var(--accent); }}
  footer {{ text-align: center; color: var(--text3); font-size: .8rem;
            margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
  @media (max-width: 600px) {{ .hero {{ flex-direction: column; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡 STARKER Security Report v{VERSION}</h1>
    <p>Auditoria de: <strong>{domain}</strong> &nbsp;|&nbsp; Gerado em: {generated}</p>
  </header>

  <div class="hero">
    <div class="score-card">
      <div class="gauge-wrap">
        <div class="gauge-bg"></div>
        <div class="gauge-fill"></div>
      </div>
      <div class="score-num">{score}</div>
      <div class="score-label">Score de segurança / 100</div>
      <div class="risk-badge">{risk}</div>
    </div>
    <div class="meta-card">
      <h3>📋 Resumo da auditoria</h3>
      <div class="meta-grid">
        <span class="k">Alvo</span>        <span class="v">{details.get('url','')}</span>
        <span class="k">URL final</span>   <span class="v">{details.get('final_url','—')}</span>
        <span class="k">IPs</span>         <span class="v">{', '.join(details.get('ips',[])) or '—'}</span>
        <span class="k">IPv6</span>        <span class="v">{', '.join(details.get('ipv6',[])) or '—'}</span>
        <span class="k">WAF/CDN</span>     <span class="v">{details.get('waf') or 'Não detectado'}</span>
        <span class="k">SPF</span>         <span class="v">{'✓ Presente' if dns.get('spf') else '✗ Ausente'}</span>
        <span class="k">DMARC</span>       <span class="v">{'✓ Presente' if dns.get('dmarc') else '✗ Ausente'}</span>
        <span class="k">DNSSEC</span>      <span class="v">{'✓ Ativo' if dns.get('dnssec') else 'Não detectado'}</span>
        <span class="k">Duração</span>     <span class="v">{details.get('elapsed','?')}s</span>
      </div>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{len(penalties)}</div>Penalidades</div>
    <div class="stat"><div class="n">{len(details.get('open_ports',[]))}</div>Portas abertas</div>
    <div class="stat"><div class="n">{len(details.get('subdomains',[]))}</div>Subdomínios</div>
    <div class="stat"><div class="n">{len([k for k in details.get('headers',{}) if k in SECURITY_HEADERS])}</div>Headers OK</div>
    <div class="stat"><div class="n">{ssl.get('days_until_expiry','?')}</div>Dias cert. SSL</div>
  </div>

  <div class="section">
    <h2>⚠ Findings ({len(findings)})</h2>
    <ul class="findings">{findings_html}</ul>
  </div>

  {'<div class="section"><h2>🔐 SSL / TLS</h2><table><tbody>' +
    row("TLS version", ssl.get('tls_version')) +
    row("Cipher suite", ssl.get('cipher')) +
    row("Protocolo(s) suportados", ', '.join(ssl.get('supported_protocols',[]))) +
    row("Issuer", ssl.get('issuer')) +
    row("Common Name", ssl.get('common_name')) +
    row("Emitido em", ssl.get('not_before')) +
    row("Expira em", ssl.get('not_after')) +
    row("Dias restantes", ssl.get('days_until_expiry')) +
    row("SANs", ', '.join((ssl.get('sans') or [])[:6])) +
    '</tbody></table></div>' if ssl else ''}

  {'<div class="section"><h2>🌐 DNS</h2><table><tbody>' +
    row("IPv4", ', '.join(dns.get('ips',[]))) +
    row("IPv6", ', '.join(dns.get('ipv6',[]))) +
    row("NS", ', '.join(dns.get('ns',[]))) +
    row("MX", ', '.join(dns.get('mx',[]))) +
    row("SPF", dns.get('spf') or '✗ Ausente') +
    row("DMARC", dns.get('dmarc') or '✗ Ausente') +
    row("DNSSEC", '✓ Ativo' if dns.get('dnssec') else 'Não detectado') +
    '</tbody></table></div>' if dns else ''}

  {'<div class="section"><h2>🔒 WHOIS</h2><table><tbody>' +
    row("Registrar", whois_d.get('registrar')) +
    row("Organização", whois_d.get('org')) +
    row("País", whois_d.get('country')) +
    row("Criação", whois_d.get('creation_date')) +
    row("Atualização", whois_d.get('updated_date')) +
    row("Expiração", whois_d.get('expiration_date')) +
    '</tbody></table></div>' if whois_d else ''}

  {'<div class="section"><h2>🔌 Portas Abertas</h2><table><thead><tr><th>Porta</th><th>Serviço</th><th>IP</th><th>Risco</th></tr></thead><tbody>' + ports_html + '</tbody></table></div>' if ports_html else ''}

  {'<div class="section"><h2>🌍 Subdomínios</h2><ul class="sub-list">' + subdomains_html + '</ul></div>' if subdomains_html else ''}

  <div class="section">
    <h2>📨 Headers HTTP</h2>
    <table><thead><tr><th>Header</th><th>Valor</th></tr></thead>
    <tbody>{headers_html}</tbody></table>
  </div>

  <footer>
    STARKER Security Scanner v{VERSION} &nbsp;·&nbsp;
    Relatório gerado automaticamente. Use apenas em domínios próprios ou com autorização.
  </footer>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# =========================================================
# RELATÓRIO: JSON
# =========================================================

def generate_json_report(report: dict, output_path: Path):
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False, default=str)


# =========================================================
# RELATÓRIO: CSV
# =========================================================

def generate_csv_report(report: dict, output_path: Path):
    details = report["details"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["STARKER Security Report v" + VERSION, report["target"]])
        w.writerow(["Generated At", report["generated_at"]])
        w.writerow(["Score", report["score"]])
        w.writerow(["Risk Level", report["risk_level"]])
        w.writerow(["Elapsed", details.get("elapsed")])
        w.writerow([])
        w.writerow(["=== FINDINGS ==="])
        for f in report["findings"]:
            w.writerow([f])
        w.writerow([])
        w.writerow(["=== DETAILS ==="])
        w.writerow(["Field", "Value"])
        w.writerow(["URL", details.get("url")])
        w.writerow(["Final URL", details.get("final_url")])
        w.writerow(["IPs", ", ".join(details.get("ips", []))])
        w.writerow(["IPv6", ", ".join(details.get("ipv6", []))])
        w.writerow(["WAF", details.get("waf") or "N/A"])
        dns = details.get("dns", {})
        w.writerow(["SPF", dns.get("spf") or "Ausente"])
        w.writerow(["DMARC", dns.get("dmarc") or "Ausente"])
        ssl = details.get("ssl", {})
        w.writerow(["TLS Version", ssl.get("tls_version")])
        w.writerow(["SSL Days Left", ssl.get("days_until_expiry")])
        w.writerow([])
        w.writerow(["=== OPEN PORTS ==="])
        w.writerow(["Port", "Service", "IP"])
        for p in details.get("open_ports", []):
            w.writerow([p["port"], p["service"], p["ip"]])
        w.writerow([])
        w.writerow(["=== SUBDOMAINS ==="])
        for s in details.get("subdomains", []):
            w.writerow([s])
        w.writerow([])
        w.writerow(["=== HEADERS ==="])
        w.writerow(["Header", "Value"])
        for k, v in details.get("headers", {}).items():
            w.writerow([k, v])
        whois_d = details.get("whois", {})
        if whois_d:
            w.writerow([])
            w.writerow(["=== WHOIS ==="])
            for k, v in whois_d.items():
                w.writerow([k, v])


# =========================================================
# BUILDER & SUMMARY
# =========================================================

def build_report(domain: str, output: str | None, fmt: str,
                 state: AuditState, target_data: dict):
    final_score = state.final_score()
    report = {
        "target":       domain,
        "generated_at": get_now_utc().isoformat(),
        "version":      VERSION,
        "score":        final_score,
        "risk_level":   get_risk_level(final_score),
        "findings":     state.findings,
        "details":      target_data,
    }
    path = determine_output_path(domain, output, fmt)

    if fmt == "json":
        generate_json_report(report, path)
    elif fmt == "html":
        generate_html_report(domain, report, path)
    elif fmt == "csv":
        generate_csv_report(report, path)
    else:
        raise ValueError(f"Formato inválido: {fmt}")

    print(f"\n[+] Relatório salvo em: {path}")


def print_summary(domain: str, state: AuditState, target_data: dict):
    banner("[+] Executive Summary")
    final = state.final_score()
    risk  = get_risk_level(final)
    color_map = {"LOW": "\033[92m", "MODERATE": "\033[93m",
                 "HIGH": "\033[91m", "CRITICAL": "\033[31m"}
    reset = "\033[0m"
    color = color_map.get(risk, "")

    print(f"  Alvo              : {domain}")
    print(f"  Score             : {color}{final}/100{reset}")
    print(f"  Risco             : {color}{risk}{reset}")
    print(f"  Penalidades       : {len([f for f in state.findings if f.startswith('[-')])}")
    print(f"  Portas abertas    : {len(target_data.get('open_ports', []))}")
    print(f"  Subdomínios       : {len(target_data.get('subdomains', []))}")
    print(f"  WAF/CDN           : {target_data.get('waf') or 'Não detectado'}")
    print(f"  Duração do scan   : {state.elapsed()}s")


# =========================================================
# CLI
# =========================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"STARKER Security Scanner v{VERSION} — Enterprise Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python scanner.py example.com
  python scanner.py https://example.com --format html
  python scanner.py example.com --skip-ports --skip-subdomains
  python scanner.py example.com --format html --verbose
        """,
    )
    parser.add_argument("target",            help="Domínio ou URL alvo")
    parser.add_argument("-o", "--output",    help="Arquivo de saída (sem extensão = automático)")
    parser.add_argument("--format",          choices=["json", "html", "csv"], default="json",
                        help="Formato do relatório (padrão: json)")
    parser.add_argument("--timeout",         type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout em segundos (padrão: {DEFAULT_TIMEOUT})")
    parser.add_argument("--workers",         type=int, default=DEFAULT_WORKERS,
                        help=f"Workers para port scan (padrão: {DEFAULT_WORKERS})")
    parser.add_argument("--skip-whois",      action="store_true", help="Pular WHOIS")
    parser.add_argument("--skip-ports",      action="store_true", help="Pular scan de portas")
    parser.add_argument("--skip-subdomains", action="store_true", help="Pular enumeração de subdomínios")
    parser.add_argument("--verbose",         action="store_true", help="Modo verboso (exibe todos os headers)")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        _, domain = normalize_target(args.target)
    except ValueError as exc:
        print(f"Erro de entrada: {exc}")
        sys.exit(1)

    banner(f"STARKER SECURITY SCANNER v{VERSION}")
    print(f"  Alvo: {domain}")
    print(f"  Início: {get_now_utc().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if not HAS_DNSPYTHON:
        print("  [AVISO] dnspython não instalado — análise DNS limitada")
        print("          Execute: pip install dnspython")

    state, target_data = run_audit(
        domain,
        timeout=args.timeout,
        workers=args.workers,
        skip_whois=args.skip_whois,
        skip_ports=args.skip_ports,
        skip_subdomains=args.skip_subdomains,
        verbose=args.verbose,
    )

    print_summary(domain, state, target_data)
    build_report(domain, args.output, args.format, state, target_data)


if __name__ == "__main__":
    main()