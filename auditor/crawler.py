from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .extractors import (
    detect_scrape_patterns,
    extract_js_endpoints,
    extract_visible_data,
    json_shape,
    normalize_link,
    parse_html,
    query_params,
)
from .http_client import SafeHttpClient
from .models import Endpoint, Form, PageRecord, VisibleData
from .scope import AuthorizedTarget, same_scope


@dataclass
class CrawlResult:
    pages: list[PageRecord] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    visible_data: list[VisibleData] = field(default_factory=list)
    scrape_patterns: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    json_shapes: dict[str, list[str]] = field(default_factory=dict)

    def to_inventory(self) -> dict[str, object]:
        return {
            "pages": [page.to_dict() for page in self.pages],
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
            "forms": [form.to_dict() for form in self.forms],
            "scripts": sorted(set(self.scripts)),
            "visible_data": [item.to_dict() for item in self.visible_data],
            "scrape_patterns": self.scrape_patterns,
            "json_shapes": self.json_shapes,
            "errors": self.errors,
            "skipped": self.skipped,
        }


class Crawler:
    def __init__(
        self,
        client: SafeHttpClient,
        target: AuthorizedTarget,
        max_pages: int = 100,
        max_depth: int = 2,
        max_scripts: int = 30,
    ) -> None:
        self.client = client
        self.target = target
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_scripts = max_scripts

    def crawl(self, start_url: str) -> CrawlResult:
        result = CrawlResult()
        queue: deque[tuple[str, int, str]] = deque()
        visited: set[str] = set()
        discovered_urls: set[str] = set()

        queue.append((start_url, 0, "start"))
        for seed in self._seed_urls(start_url):
            queue.append((seed, 0, "well-known"))

        fetched_scripts: set[str] = set()

        while queue and len(visited) < self.max_pages:
            url, depth, source = queue.popleft()
            normalized = self._normalize_visit_url(url)
            if not normalized or normalized in visited:
                continue
            if not same_scope(normalized, self.target):
                result.skipped.append(normalized)
                continue

            visited.add(normalized)
            response = self.client.fetch(normalized)
            record = PageRecord(
                url=normalized,
                final_url=response.final_url,
                status_code=response.status_code,
                content_type=response.content_type,
                headers=response.headers,
                error=response.error,
            )
            result.pages.append(record)
            result.endpoints.append(
                Endpoint(
                    url=normalized,
                    source=source,
                    status_code=response.status_code,
                    content_type=response.content_type,
                    params=query_params(normalized),
                )
            )
            discovered_urls.add(normalized)

            if response.error:
                result.errors.append(f"{normalized}: {response.error}")
                continue

            text = response.text
            content_type = response.content_type.lower()
            result.visible_data.extend(extract_visible_data(normalized, text))

            if "json" in content_type:
                shape = json_shape(text)
                if shape:
                    result.json_shapes[normalized] = shape
                continue

            if not _looks_textual(content_type, normalized):
                continue

            if normalized.endswith("/robots.txt"):
                for linked in self._parse_robots(normalized, text):
                    self._enqueue(queue, linked, depth + 1, "robots.txt", result)
                    discovered_urls.add(linked)
                continue

            if normalized.endswith("/sitemap.xml") or "xml" in content_type:
                for linked in self._parse_sitemap(normalized, text):
                    self._enqueue(queue, linked, depth + 1, "sitemap.xml", result)
                    discovered_urls.add(linked)
                continue

            parsed = parse_html(normalized, text)
            record.title = parsed.title
            result.forms.extend(parsed.forms)

            for form in parsed.forms:
                if same_scope(form.action, self.target):
                    result.endpoints.append(
                        Endpoint(
                            url=form.action,
                            source="form",
                            method=form.method,
                            params=sorted(set(form.fields)),
                        )
                    )
                    discovered_urls.add(form.action)
                else:
                    result.skipped.append(form.action)

            for link in parsed.links:
                if not link:
                    continue
                discovered_urls.add(link)
                if depth < self.max_depth:
                    self._enqueue(queue, link, depth + 1, "link", result)

            for script in parsed.scripts:
                if not script:
                    continue
                result.scripts.append(script)
                discovered_urls.add(script)
                if (
                    len(fetched_scripts) < self.max_scripts
                    and script not in fetched_scripts
                    and same_scope(script, self.target)
                ):
                    fetched_scripts.add(script)
                    script_response = self.client.fetch(script, max_bytes=750_000)
                    script_text = script_response.text
                    result.visible_data.extend(extract_visible_data(script, script_text))
                    for endpoint in extract_js_endpoints(script, script_text):
                        if same_scope(endpoint, self.target):
                            discovered_urls.add(endpoint)
                            result.endpoints.append(
                                Endpoint(
                                    url=endpoint,
                                    source="javascript",
                                    params=query_params(endpoint),
                                )
                            )
                            if depth < self.max_depth:
                                self._enqueue(
                                    queue,
                                    endpoint,
                                    depth + 1,
                                    "javascript",
                                    result,
                                )
                        else:
                            result.skipped.append(endpoint)

        result.scrape_patterns = detect_scrape_patterns(
            [url for url in discovered_urls if same_scope(url, self.target)]
        )
        result.endpoints = _dedupe_endpoints(result.endpoints)
        result.visible_data = _dedupe_visible_data(result.visible_data)
        result.forms = _dedupe_forms(result.forms)
        return result

    def _seed_urls(self, start_url: str) -> list[str]:
        parsed = urlparse(start_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        return [f"{root}/robots.txt", f"{root}/sitemap.xml"]

    def _enqueue(
        self,
        queue: deque[tuple[str, int, str]],
        url: str,
        depth: int,
        source: str,
        result: CrawlResult,
    ) -> None:
        normalized = self._normalize_visit_url(url)
        if not normalized:
            return
        if same_scope(normalized, self.target):
            queue.append((normalized, depth, source))
        else:
            result.skipped.append(normalized)

    def _normalize_visit_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return ""
        if len(url) > 2000:
            return ""
        parsed = parsed._replace(fragment="")
        return parsed.geturl()

    def _parse_robots(self, base_url: str, text: str) -> list[str]:
        links: list[str] = []
        for line in text.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            key, _, value = clean.partition(":")
            if key.lower() in {"sitemap", "allow", "disallow"} and value.strip():
                candidate = value.strip()
                if candidate == "/":
                    continue
                links.append(normalize_link(base_url, candidate))
        return [link for link in links if link]

    def _parse_sitemap(self, base_url: str, text: str) -> list[str]:
        import xml.etree.ElementTree as ET

        links: list[str] = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return links
        for element in root.iter():
            if element.tag.endswith("loc") and element.text:
                links.append(normalize_link(base_url, element.text.strip()))
        return [link for link in links if link]


def _looks_textual(content_type: str, url: str) -> bool:
    lowered = content_type.lower()
    if any(kind in lowered for kind in ("text", "html", "xml", "javascript", "json")):
        return True
    path = urlparse(url).path.lower()
    return path.endswith((".html", ".htm", ".js", ".txt", ".xml", ".json", "/"))


def _dedupe_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str]] = set()
    unique: list[Endpoint] = []
    for endpoint in endpoints:
        key = (endpoint.method, endpoint.url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(endpoint)
    return unique


def _dedupe_visible_data(items: list[VisibleData]) -> list[VisibleData]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[VisibleData] = []
    for item in items:
        key = (item.url, item.data_type, item.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _dedupe_forms(forms: list[Form]) -> list[Form]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Form] = []
    for form in forms:
        key = (form.page_url, form.action, form.method)
        if key in seen:
            continue
        seen.add(key)
        unique.append(form)
    return unique
