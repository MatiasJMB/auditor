from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse


class AuthorizationError(RuntimeError):
    """Raised when a target is not authorized for auditing."""


@dataclass
class AuthorizedTarget:
    domain: str
    allow_subdomains: bool = False
    max_depth: int = 2
    max_pages: int = 100
    notes: str = ""


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL vacia")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Solo se permiten URLs http o https")
    if not parsed.hostname:
        raise ValueError("La URL no contiene host")

    path = parsed.path or "/"
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=path,
        fragment="",
    )
    return urlunparse(normalized)


def host_from_url(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    if not parsed.hostname:
        raise ValueError("La URL no contiene host")
    return parsed.hostname.lower()


def same_scope(url: str, target: AuthorizedTarget) -> bool:
    try:
        host = host_from_url(url)
    except ValueError:
        return False
    domain = target.domain.lower()
    return host == domain or (
        target.allow_subdomains and host.endswith("." + domain)
    )


def load_authorized_targets(path: str | Path) -> list[AuthorizedTarget]:
    auth_path = Path(path)
    if not auth_path.exists():
        raise AuthorizationError(
            f"No existe el archivo de autorizacion: {auth_path}"
        )

    text = auth_path.read_text(encoding="utf-8")
    if auth_path.suffix.lower() == ".json":
        raw = json.loads(text)
        items = raw.get("targets", raw if isinstance(raw, list) else [])
    else:
        items = _parse_targets_yaml_subset(text)

    targets: list[AuthorizedTarget] = []
    for item in items:
        domain = str(item.get("domain", "")).strip().lower()
        if not domain:
            continue
        targets.append(
            AuthorizedTarget(
                domain=domain,
                allow_subdomains=bool(item.get("allow_subdomains", False)),
                max_depth=int(item.get("max_depth", 2)),
                max_pages=int(item.get("max_pages", 100)),
                notes=str(item.get("notes", "")),
            )
        )
    return targets


def require_authorized(
    url: str,
    auth_file: str | Path = "authorized_targets.yaml",
) -> AuthorizedTarget:
    normalized = normalize_url(url)
    targets = load_authorized_targets(auth_file)
    for target in targets:
        if same_scope(normalized, target):
            return target
    host = host_from_url(normalized)
    raise AuthorizationError(
        f"El host {host} no esta autorizado en {auth_file}"
    )


def effective_limits(
    requested_depth: int,
    requested_max_pages: int,
    target: AuthorizedTarget,
) -> tuple[int, int, list[str]]:
    notes: list[str] = []
    depth = min(requested_depth, target.max_depth)
    max_pages = min(requested_max_pages, target.max_pages)
    if depth < requested_depth:
        notes.append(
            f"depth limitado de {requested_depth} a {depth} por autorizacion"
        )
    if max_pages < requested_max_pages:
        notes.append(
            f"max_pages limitado de {requested_max_pages} a {max_pages} por autorizacion"
        )
    return depth, max_pages, notes


def _parse_targets_yaml_subset(text: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip() or line.strip() == "targets:":
            continue

        stripped = line.strip()
        if stripped.startswith("- "):
            if current:
                items.append(current)
            current = {}
            rest = stripped[2:].strip()
            if rest:
                key, value = _split_yaml_pair(rest)
                current[key] = _parse_scalar(value)
            continue

        if current is not None and ":" in stripped:
            key, value = _split_yaml_pair(stripped)
            current[key] = _parse_scalar(value)

    if current:
        items.append(current)
    return items


def _split_yaml_pair(text: str) -> tuple[str, str]:
    key, value = text.split(":", 1)
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> object:
    value = value.strip().strip('"').strip("'")
    lower = value.lower()
    if lower in {"true", "yes", "si"}:
        return True
    if lower in {"false", "no"}:
        return False
    try:
        return int(value)
    except ValueError:
        return value

