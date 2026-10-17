from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from .models import Form, VisibleData


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{1,4}\)?[\s.-]){2,4}\d{3,4}(?![\w.])"
)
ABS_URL_RE = re.compile(r"https?://[^\s'\"<>\\)]+", re.I)
TOKEN_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|secret|client[_-]?secret|bearer)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})"
)
PATH_RE = re.compile(
    r"['\"]((?:/|\./|\.\./)?(?:api|v[0-9]|graphql|admin|auth|login|logout|users|customers|products|orders|search|wp-json|rest|ajax|upload|download)[^'\"\s<>]{0,180})['\"]",
    re.I,
)
DOCUMENT_RE = re.compile(r"\.(?:pdf|docx?|xlsx?|csv|zip|rar|7z|sql|bak|backup)(?:$|[?#])", re.I)
INTERNAL_HINT_RE = re.compile(
    r"\b(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|(?:dev|staging|qa|internal)\.[a-z0-9.-]+|[a-z0-9.-]+\.(?:dev|staging|qa|internal))\b",
    re.I,
)


@dataclass
class ParsedHtml:
    title: str = ""
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    text: str = ""


class LinkFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ParsedHtml()
        self._in_title = False
        self._in_script = False
        self._current_form: dict[str, object] | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()

        if tag == "title":
            self._in_title = True
        if tag == "script":
            self._in_script = True
            src = attrs_dict.get("src")
            if src:
                self.result.scripts.append(normalize_link(self.base_url, src))
        if tag in {"a", "link", "area"}:
            href = attrs_dict.get("href")
            if href:
                self.result.links.append(normalize_link(self.base_url, href))
        if tag in {"img", "iframe", "source"}:
            src = attrs_dict.get("src")
            if src:
                self.result.links.append(normalize_link(self.base_url, src))
        if tag == "form":
            action = attrs_dict.get("action") or self.base_url
            self._current_form = {
                "action": normalize_link(self.base_url, action),
                "method": (attrs_dict.get("method") or "GET").upper(),
                "fields": [],
            }
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attrs_dict.get("name") or attrs_dict.get("id")
            if name:
                fields = self._current_form["fields"]
                assert isinstance(fields, list)
                fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_script = False
        if tag == "form" and self._current_form is not None:
            self.result.forms.append(
                Form(
                    page_url=self.base_url,
                    action=str(self._current_form["action"]),
                    method=str(self._current_form["method"]),
                    fields=list(self._current_form["fields"]),
                )
            )
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.result.title += data.strip()
        elif not self._in_script:
            clean = data.strip()
            if clean:
                self._text_parts.append(clean)

    def close(self) -> None:
        super().close()
        self.result.text = " ".join(self._text_parts)


def parse_html(base_url: str, html_text: str) -> ParsedHtml:
    parser = LinkFormParser(base_url)
    parser.feed(html_text)
    parser.close()
    return parser.result


def normalize_link(base_url: str, link: str) -> str:
    link = html.unescape(link.strip())
    if not link or link.startswith(("mailto:", "tel:", "javascript:", "#")):
        return ""
    joined = urljoin(base_url, link)
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return ""
    parsed = parsed._replace(fragment="")
    return urlunparse(parsed)


def query_params(url: str) -> list[str]:
    return sorted(parse_qs(urlparse(url).query).keys())


def extract_js_endpoints(base_url: str, js_text: str) -> list[str]:
    found: set[str] = set()
    for match in ABS_URL_RE.findall(js_text):
        found.add(clean_candidate_url(base_url, match))
    for match in PATH_RE.findall(js_text):
        found.add(clean_candidate_url(base_url, match))
    return sorted(url for url in found if url)


def clean_candidate_url(base_url: str, candidate: str) -> str:
    candidate = candidate.strip().strip("'\"`),;")
    if not candidate or any(token in candidate for token in ("${", "<", ">", "\n", "\r")):
        return ""
    return normalize_link(base_url, candidate)


def extract_phone_candidates(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in PHONE_RE.finditer(text):
        value = match.group(0).strip()
        digits = re.sub(r"\D", "", value)
        if not 8 <= len(digits) <= 15:
            continue
        if re.fullmatch(r"\d{4}[-/]\d{1,2}[-/]\d{1,2}", value):
            continue
        if "." in value:
            continue
        parts = value.split()
        if len(parts) == 4 and parts[0] == "0" and parts[1] == "0":
            continue
        separator_count = len(re.findall(r"[\s()-]", value))
        if not value.startswith("+") and "(" not in value and separator_count < 2:
            continue
        if value not in seen:
            seen.add(value)
            values.append(value)
    return values


def extract_visible_data(url: str, text: str) -> list[VisibleData]:
    findings: list[VisibleData] = []
    seen: set[tuple[str, str]] = set()

    for data_type, regex in (
        ("email", EMAIL_RE),
        ("url", ABS_URL_RE),
    ):
        for match in regex.findall(text):
            value = match if isinstance(match, str) else match[0]
            value = value.strip()
            if data_type == "url" and not INTERNAL_HINT_RE.search(value):
                continue
            _append_unique(findings, seen, url, data_type, value)

    for value in extract_phone_candidates(text):
        _append_unique(findings, seen, url, "phone", value)

    for match in TOKEN_RE.finditer(text):
        label = match.group(1)
        token = sanitize_secret(match.group(2))
        _append_unique(findings, seen, url, "possible_secret", f"{label}={token}")

    for match in ABS_URL_RE.findall(text):
        if DOCUMENT_RE.search(match):
            _append_unique(findings, seen, url, "document_url", match.strip())

    if INTERNAL_HINT_RE.search(text):
        for snippet in _snippets(text, INTERNAL_HINT_RE):
            _append_unique(findings, seen, url, "internal_hint", snippet)

    return findings


def detect_scrape_patterns(urls: list[str]) -> dict[str, list[str]]:
    patterns = {
        "pagination": [],
        "search_or_filter": [],
        "downloadable_documents": [],
        "api_like": [],
    }
    for url in sorted(set(urls)):
        parsed = urlparse(url)
        params = set(parse_qs(parsed.query).keys())
        path = parsed.path.lower()
        if params.intersection({"page", "p", "offset", "limit", "cursor", "start"}):
            patterns["pagination"].append(url)
        if params.intersection({"q", "query", "search", "filter", "category", "tag"}):
            patterns["search_or_filter"].append(url)
        if DOCUMENT_RE.search(url):
            patterns["downloadable_documents"].append(url)
        if re.search(r"/(?:api|v\d|graphql|wp-json|rest|ajax)(?:/|$)", path):
            patterns["api_like"].append(url)
    return patterns


def json_shape(text: str, max_keys: int = 40) -> list[str]:
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    keys: set[str] = set()

    def visit(value: object, prefix: str = "") -> None:
        if len(keys) >= max_keys:
            return
        if isinstance(value, dict):
            for key, nested in value.items():
                full = f"{prefix}.{key}" if prefix else str(key)
                keys.add(full)
                visit(nested, full)
        elif isinstance(value, list) and value:
            visit(value[0], prefix)

    visit(data)
    return sorted(keys)[:max_keys]


def sanitize_secret(value: str) -> str:
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _append_unique(
    findings: list[VisibleData],
    seen: set[tuple[str, str]],
    url: str,
    data_type: str,
    value: str,
) -> None:
    key = (data_type, value)
    if key in seen:
        return
    seen.add(key)
    findings.append(VisibleData(url=url, data_type=data_type, value=value[:300]))


def _snippets(text: str, regex: re.Pattern[str], window: int = 60) -> list[str]:
    snippets: list[str] = []
    for match in regex.finditer(text):
        start = max(match.start() - window, 0)
        end = min(match.end() + window, len(text))
        snippets.append(" ".join(text[start:end].split())[:220])
        if len(snippets) >= 10:
            break
    return snippets
