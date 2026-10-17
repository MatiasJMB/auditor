from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from .crawler import CrawlResult
from .http_client import UA_PROFILES, SafeHttpClient
from .models import Finding
from .scope import AuthorizedTarget, same_scope


SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS ausente",
        "El navegador no recibe una politica para forzar HTTPS en visitas futuras.",
        "Configurar Strict-Transport-Security con max-age adecuado y evaluar includeSubDomains.",
    ),
    "content-security-policy": (
        "CSP ausente",
        "Sin Content-Security-Policy aumenta el impacto de inyecciones de contenido.",
        "Definir una CSP ajustada a los origenes reales del sitio.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options ausente",
        "El navegador podria interpretar contenido con un tipo distinto al declarado.",
        "Agregar X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "Referrer-Policy ausente",
        "URLs internas o parametros podrian filtrarse como referrer hacia terceros.",
        "Configurar Referrer-Policy, por ejemplo strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "Permissions-Policy ausente",
        "No se restringen explicitamente APIs sensibles del navegador.",
        "Definir Permissions-Policy con permisos minimos.",
    ),
}

COMMON_EXPOSURES = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
    "/debug",
    "/swagger.json",
    "/openapi.json",
    "/api/docs",
]


def build_findings(
    start_url: str,
    target: AuthorizedTarget,
    crawl: CrawlResult,
    client: SafeHttpClient,
    include_active_checks: bool = True,
    include_cloak_check: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_headers_and_cookies(crawl))
    findings.extend(check_cors(crawl))
    findings.extend(check_tls(start_url))
    findings.extend(check_scrapeability(crawl))
    if include_cloak_check:
        findings.extend(check_cloaking_and_gating(start_url, target, client))
    if include_active_checks:
        findings.extend(check_options_methods(start_url, target, client))
        findings.extend(check_common_exposures(start_url, target, client))
        findings.extend(check_rate_limit_signals(start_url, client))
    return _dedupe_findings(findings)


def check_cloaking_and_gating(
    start_url: str,
    target: AuthorizedTarget,
    client: SafeHttpClient,
) -> list[Finding]:
    """Pide la URL inicial con varios perfiles de cliente y detecta:

    - Cloaking: contenido sustancialmente distinto segun el User-Agent
      (tecnica habitual en phishing para ocultarse de analistas y bots).
    - Gate JS/cookie: paginas-cargador que fijan una cookie y recargan,
      lo que impide a un crawler sin JS ver el contenido real.
    """
    if not same_scope(start_url, target):
        return []

    samples: dict[str, dict[str, object]] = {}
    for name, ua in UA_PROFILES.items():
        response = client.fetch(
            start_url,
            headers={"User-Agent": ua, "Accept-Language": "es-CL,es;q=0.9"},
        )
        body = response.text if response.status_code else ""
        samples[name] = {
            "status": response.status_code,
            "final_url": response.final_url,
            "host": urlparse(response.final_url or start_url).hostname or "",
            "title": _title_of(body),
            "size": len(body),
            "body": body,
        }

    findings: list[Finding] = []
    findings.extend(_cloaking_findings(start_url, samples))
    findings.extend(_gating_findings(start_url, samples))
    return findings


def _cloaking_findings(
    start_url: str, samples: dict[str, dict[str, object]]
) -> list[Finding]:
    usable = {
        name: data
        for name, data in samples.items()
        if data["status"] == 200 and int(data["size"]) > 0
    }
    if len(usable) < 2:
        return []

    names = list(usable)
    sizes = {name: int(usable[name]["size"]) for name in names}
    hosts = {str(usable[name]["host"]) for name in names}

    min_ratio = 1.0
    worst_pair = ("", "")
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            ratio = _similarity(str(usable[a]["body"]), str(usable[b]["body"]))
            if ratio < min_ratio:
                min_ratio = ratio
                worst_pair = (a, b)

    smallest, largest = min(sizes.values()), max(sizes.values())
    size_ratio = largest / smallest if smallest else float("inf")

    divergent_hosts = len(hosts) > 1
    divergent_size = size_ratio >= 1.5 and (largest - smallest) > 1500
    divergent_body = min_ratio < 0.5

    if not (divergent_hosts or divergent_size or divergent_body):
        return []

    detail = "; ".join(
        f"{name}: HTTP {usable[name]['status']}, {sizes[name]} bytes, "
        f"titulo={usable[name]['title'] or '-'!r}"
        for name in names
    )
    reasons = []
    if divergent_hosts:
        reasons.append(f"hosts finales distintos ({', '.join(sorted(hosts))})")
    if divergent_size:
        reasons.append(f"tamano varia {size_ratio:.1f}x entre perfiles")
    if divergent_body:
        reasons.append(
            f"similitud minima {min_ratio:.0%} entre {worst_pair[0]} y {worst_pair[1]}"
        )

    return [
        Finding(
            severity="high",
            title="Cloaking por User-Agent detectado",
            url=start_url,
            evidence=f"{'; '.join(reasons)}. Muestras -> {detail}",
            risk=(
                "El sitio entrega contenido distinto segun el cliente. Es una tecnica "
                "comun de phishing y fraude para mostrar una pagina inocua a analistas, "
                "bots y escritorio, mientras sirve el contenido malicioso al objetivo "
                "(por ejemplo navegadores moviles)."
            ),
            recommendation=(
                "Comparar manualmente cada variante con un navegador real, conservar "
                "evidencia de todas las versiones y, si el contenido es malicioso, "
                "reportar el dominio al registrador/hosting y a los CERT correspondientes."
            ),
            category="cloaking",
            confidence="confirmed",
        )
    ]


def _gating_findings(
    start_url: str, samples: dict[str, dict[str, object]]
) -> list[Finding]:
    findings: list[Finding] = []
    for name, data in samples.items():
        body = str(data["body"])
        if int(data["size"]) > 4000 or not body:
            continue
        lowered = body.lower()
        reloads = "location.reload" in lowered or "location.href" in lowered
        sets_cookie = "document.cookie" in lowered
        meta_refresh = 'http-equiv="refresh"' in lowered or "http-equiv='refresh'" in lowered
        if (reloads and sets_cookie) or (meta_refresh and "<body" in lowered):
            mechanism = []
            if sets_cookie:
                mechanism.append("fija cookie via JS")
            if reloads:
                mechanism.append("recarga la pagina")
            if meta_refresh:
                mechanism.append("meta refresh")
            findings.append(
                Finding(
                    severity="medium",
                    title="Contenido detras de gate JS/cookie",
                    url=start_url,
                    evidence=(
                        f"Perfil {name}: respuesta de {data['size']} bytes que "
                        f"{' y '.join(mechanism)} antes de mostrar contenido."
                    ),
                    risk=(
                        "El contenido real solo aparece tras ejecutar JavaScript y "
                        "presentar una cookie, por lo que un crawler sin navegador no "
                        "ve la pagina efectiva. Es un filtro anti-bot/anti-analisis "
                        "habitual en kits de phishing."
                    ),
                    recommendation=(
                        "Auditar con un navegador real o repitiendo la peticion con la "
                        "cookie ya fijada; no tomar el cargador inicial como el "
                        "contenido del sitio."
                    ),
                    category="cloaking",
                    confidence="confirmed",
                )
            )
            break
    return findings


def _title_of(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return match.group(1).strip()[:120] if match else ""


def _similarity(a: str, b: str, limit: int = 20000) -> float:
    return SequenceMatcher(None, a[:limit], b[:limit]).quick_ratio()


def check_headers_and_cookies(crawl: CrawlResult) -> list[Finding]:
    findings: list[Finding] = []
    if not crawl.pages:
        return findings
    page = crawl.pages[0]
    headers = {key.lower(): value for key, value in page.headers.items()}

    for header, (title, risk, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            severity = "medium" if header in {"strict-transport-security", "content-security-policy"} else "low"
            findings.append(
                Finding(
                    severity=severity,
                    title=title,
                    url=page.url,
                    evidence=f"No se observo el header {header}",
                    risk=risk,
                    recommendation=recommendation,
                    category="headers",
                )
            )

    frame_policy = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    if not frame_policy and "frame-ancestors" not in csp:
        findings.append(
            Finding(
                severity="medium",
                title="Proteccion anti-clickjacking ausente",
                url=page.url,
                evidence="No se observo X-Frame-Options ni frame-ancestors en CSP",
                risk="El sitio podria ser embebido en iframes por terceros.",
                recommendation="Agregar frame-ancestors en CSP o X-Frame-Options segun compatibilidad requerida.",
                category="headers",
            )
        )

    for cookie_header in _set_cookie_values(headers):
        lowered = cookie_header.lower()
        cookie_name = cookie_header.split("=", 1)[0]
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    severity="medium",
                    title="Cookie sin flags de seguridad completos",
                    url=page.url,
                    evidence=f"{cookie_name}: faltan {', '.join(missing)}",
                    risk="Cookies expuestas aumentan riesgo de robo o abuso de sesion.",
                    recommendation="Configurar cookies con Secure, HttpOnly y SameSite apropiado.",
                    category="cookies",
                )
            )

    return findings


def check_cors(crawl: CrawlResult) -> list[Finding]:
    findings: list[Finding] = []
    for page in crawl.pages:
        headers = {key.lower(): value for key, value in page.headers.items()}
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "")
        if origin == "*":
            content_type = page.content_type.lower()
            severity = "low" if any(kind in content_type for kind in ("image/", "text/css", "javascript")) else "medium"
            findings.append(
                Finding(
                    severity=severity,
                    title="CORS permisivo",
                    url=page.url,
                    evidence="Access-Control-Allow-Origin: *",
                    risk="APIs publicas pueden ser consumidas desde cualquier origen web.",
                    recommendation="Restringir CORS a origenes necesarios y revisar endpoints con datos sensibles.",
                    category="cors",
                )
            )
        if origin and credentials.lower() == "true" and origin != "*":
            findings.append(
                Finding(
                    severity="low",
                    title="CORS con credenciales habilitadas",
                    url=page.url,
                    evidence=f"Origin permitido: {origin}; credentials=true",
                    risk="Si el origen permitido es amplio, podria facilitar abuso de sesiones.",
                    recommendation="Validar que la allowlist de origenes sea estricta.",
                    category="cors",
                    confidence="suspected",
                )
            )
    return findings


def check_tls(start_url: str) -> list[Finding]:
    parsed = urlparse(start_url)
    if parsed.scheme != "https":
        return [
            Finding(
                severity="high",
                title="URL inicial sin HTTPS",
                url=start_url,
                evidence="La auditoria comenzo con esquema HTTP",
                risk="El trafico puede ser interceptado o modificado.",
                recommendation="Redirigir HTTP a HTTPS y publicar el sitio solo por TLS.",
                category="tls",
            )
        ]

    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except OSError as exc:
        return [
            Finding(
                severity="medium",
                title="No se pudo validar TLS",
                url=start_url,
                evidence=str(exc),
                risk="La auditoria no pudo confirmar el estado del certificado.",
                recommendation="Revisar certificado, cadena de confianza y compatibilidad TLS.",
                category="tls",
                confidence="suspected",
            )
        ]

    expires_raw = cert.get("notAfter")
    if not expires_raw:
        return []
    expires_at = parsedate_to_datetime(expires_raw)
    days_left = (expires_at - datetime.now(timezone.utc)).days
    if days_left < 0:
        severity = "high"
        title = "Certificado TLS expirado"
    elif days_left <= 30:
        severity = "medium"
        title = "Certificado TLS proximo a expirar"
    else:
        return []

    return [
        Finding(
            severity=severity,
            title=title,
            url=start_url,
            evidence=f"Expira en {expires_at.isoformat()} ({days_left} dias)",
            risk="Usuarios pueden recibir errores de seguridad o perder proteccion TLS.",
            recommendation="Renovar y monitorear el certificado TLS.",
            category="tls",
        )
    ]


def check_scrapeability(crawl: CrawlResult) -> list[Finding]:
    findings: list[Finding] = []
    patterns = crawl.scrape_patterns or {}

    if patterns.get("api_like"):
        findings.append(
            Finding(
                severity="medium",
                title="Endpoints API publicos detectados",
                url=patterns["api_like"][0],
                evidence=f"{len(patterns['api_like'])} rutas con apariencia API",
                risk="APIs publicas pueden facilitar extraccion automatizada de informacion.",
                recommendation="Revisar autenticacion, autorizacion, rate limit y volumen de datos devuelto.",
                category="scrapeability",
                confidence="suspected",
            )
        )

    if patterns.get("pagination"):
        findings.append(
            Finding(
                severity="medium",
                title="Paginacion enumerable detectada",
                url=patterns["pagination"][0],
                evidence=f"{len(patterns['pagination'])} URLs con parametros de paginacion",
                risk="La paginacion enumerable puede permitir recoleccion masiva de listados.",
                recommendation="Aplicar rate limiting, limites de pagina, monitoreo y controles anti-abuso.",
                category="scrapeability",
                confidence="suspected",
            )
        )

    if patterns.get("search_or_filter"):
        findings.append(
            Finding(
                severity="low",
                title="Busqueda o filtros publicos detectados",
                url=patterns["search_or_filter"][0],
                evidence=f"{len(patterns['search_or_filter'])} URLs con parametros de busqueda/filtro",
                risk="Filtros publicos pueden facilitar enumeracion del catalogo o datos publicados.",
                recommendation="Limitar resultados, agregar controles anti-automatizacion y registrar abuso.",
                category="scrapeability",
                confidence="suspected",
            )
        )

    visible_counts: dict[str, int] = {}
    example_by_type: dict[str, str] = {}
    for item in crawl.visible_data:
        visible_counts[item.data_type] = visible_counts.get(item.data_type, 0) + 1
        example_by_type.setdefault(item.data_type, item.url)

    if visible_counts.get("possible_secret"):
        findings.append(
            Finding(
                severity="high",
                title="Posibles secretos visibles en frontend",
                url=example_by_type["possible_secret"],
                evidence=f"{visible_counts['possible_secret']} posibles secretos detectados",
                risk="Credenciales o tokens expuestos pueden permitir abuso de APIs o servicios.",
                recommendation="Retirar secretos del frontend, rotarlos y mover operaciones sensibles al backend.",
                category="data_exposure",
                confidence="suspected",
            )
        )

    for data_type, title, severity, risk, recommendation in (
        (
            "email",
            "Emails scrapeables detectados",
            "medium",
            "Emails publicos pueden ser recolectados para spam, phishing o inteligencia comercial.",
            "Reducir exposicion, usar formularios de contacto o aplicar protecciones anti-scraping.",
        ),
        (
            "phone",
            "Telefonos scrapeables detectados",
            "medium",
            "Telefonos publicos pueden ser recolectados para spam o fraude.",
            "Revisar necesidad de publicacion y agregar controles anti-automatizacion.",
        ),
        (
            "document_url",
            "Documentos descargables detectados",
            "low",
            "Documentos publicos pueden contener metadatos o informacion no prevista.",
            "Revisar contenido, metadatos e indexacion de documentos publicados.",
        ),
        (
            "internal_hint",
            "Referencias internas o de ambiente detectadas",
            "medium",
            "Referencias a ambientes internos pueden facilitar reconocimiento tecnico.",
            "Eliminar URLs internas, nombres de ambientes y metadatos innecesarios del frontend.",
        ),
    ):
        if visible_counts.get(data_type):
            findings.append(
                Finding(
                    severity=severity,
                    title=title,
                    url=example_by_type[data_type],
                    evidence=f"{visible_counts[data_type]} ocurrencias detectadas",
                    risk=risk,
                    recommendation=recommendation,
                    category="data_exposure",
                    confidence="confirmed",
                )
            )

    if crawl.json_shapes:
        first_url = next(iter(crawl.json_shapes))
        findings.append(
            Finding(
                severity="medium",
                title="Respuesta JSON publica detectada",
                url=first_url,
                evidence=f"Campos observados: {', '.join(crawl.json_shapes[first_url][:12])}",
                risk="Respuestas JSON publicas pueden ser consumidas facilmente por scrapers.",
                recommendation="Revisar autenticacion, minimizacion de campos, paginacion y rate limit.",
                category="scrapeability",
                confidence="confirmed",
            )
        )

    return findings


def check_options_methods(
    start_url: str,
    target: AuthorizedTarget,
    client: SafeHttpClient,
) -> list[Finding]:
    if not same_scope(start_url, target):
        return []
    response = client.fetch(start_url, method="OPTIONS", max_bytes=2048)
    allow = response.headers.get("allow", "") or response.headers.get(
        "access-control-allow-methods", ""
    )
    risky = [method for method in ("PUT", "DELETE", "PATCH", "TRACE") if method in allow.upper()]
    if not risky:
        return []
    return [
        Finding(
            severity="medium",
            title="Metodos HTTP riesgosos anunciados",
            url=start_url,
            evidence=f"Metodos anunciados: {allow}",
            risk="Metodos de escritura o TRACE pueden aumentar la superficie si no estan protegidos.",
            recommendation="Deshabilitar metodos innecesarios o exigir autenticacion/autorizacion estricta.",
            category="methods",
            confidence="suspected",
        )
    ]


def check_common_exposures(
    start_url: str,
    target: AuthorizedTarget,
    client: SafeHttpClient,
) -> list[Finding]:
    parsed = urlparse(start_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    findings: list[Finding] = []
    for path in COMMON_EXPOSURES:
        url = root + path
        if not same_scope(url, target):
            continue
        response = client.fetch(url, max_bytes=8192)
        if response.status_code != 200:
            continue
        body = response.text[:500]
        if _looks_like_real_exposure(path, response.content_type, body):
            findings.append(
                Finding(
                    severity="high" if path in {"/.env", "/.git/config", "/backup.sql", "/dump.sql"} else "medium",
                    title="Archivo o endpoint sensible expuesto",
                    url=url,
                    evidence=f"HTTP 200 para {path}; content-type={response.content_type}",
                    risk="Archivos tecnicos publicos pueden revelar secretos, codigo, configuracion o datos.",
                    recommendation="Retirar el recurso del directorio publico y bloquearlo a nivel servidor/CDN.",
                    category="exposure",
                    confidence="confirmed",
                )
            )
    return findings


def check_rate_limit_signals(
    start_url: str,
    client: SafeHttpClient,
) -> list[Finding]:
    responses = [client.fetch(start_url, method="HEAD", max_bytes=0) for _ in range(3)]
    headers = {}
    for response in responses:
        headers.update(response.headers)
    rate_headers = [
        key
        for key in headers
        if key.lower().startswith("x-ratelimit") or key.lower() in {"retry-after", "ratelimit-limit"}
    ]
    if any(response.status_code == 429 for response in responses):
        return []
    if rate_headers:
        return []
    return [
        Finding(
            severity="info",
            title="No se observaron senales de rate limiting",
            url=start_url,
            evidence="3 solicitudes HEAD no devolvieron 429 ni headers de rate limit",
            risk="Sin controles anti-abuso visibles, el scraping puede ser mas facil de automatizar.",
            recommendation="Implementar rate limiting, monitoreo de patrones y respuestas 429 para abuso.",
            category="scrapeability",
            confidence="suspected",
        )
    ]


def _set_cookie_values(headers: dict[str, str]) -> list[str]:
    values: list[str] = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            values.extend(part.strip() for part in value.split(",") if "=" in part)
    return values


def _looks_like_real_exposure(path: str, content_type: str, body: str) -> bool:
    lowered = body.lower()
    if path == "/.env":
        return "=" in body and any(key in lowered for key in ("app_key", "secret", "password", "database", "token"))
    if path == "/.git/config":
        return "[core]" in lowered or "[remote" in lowered
    if path.endswith(".sql"):
        return "create table" in lowered or "insert into" in lowered or "dump" in lowered
    if path.endswith(".zip"):
        return "zip" in content_type.lower() or body.startswith("PK")
    if path == "/phpinfo.php":
        return "php version" in lowered or "phpinfo()" in lowered
    return bool(body.strip()) or "json" in content_type.lower() or "html" in content_type.lower()


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for finding in sorted(findings, key=lambda item: severity_order.get(item.severity, 9)):
        key = (finding.title, finding.url, finding.category)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
