"""Common crawling and endpoint discovery utilities.

Safety first: only run against authorized targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from time import perf_counter
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class InjectionPoint:
    method: str
    url: str
    parameter: str
    source: str
    form_fields: tuple[str, ...] = field(default_factory=tuple)


@dataclass(slots=True)
class HTTPResponse:
    status: int
    body: str
    elapsed: float


class _DiscoveryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[dict[str, object]] = []
        self._in_form = False
        self._active_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and attrs_map.get("href"):
            self.links.add(urljoin(self.base_url, attrs_map["href"]))
            return

        if tag.lower() == "form":
            self._in_form = True
            self._active_form = {
                "action": urljoin(self.base_url, attrs_map.get("action") or self.base_url),
                "method": (attrs_map.get("method") or "get").upper(),
                "fields": [],
            }
            return

        if self._in_form and tag.lower() in {"input", "textarea", "select"}:
            name = attrs_map.get("name")
            if name and self._active_form is not None:
                casted_fields = self._active_form["fields"]
                assert isinstance(casted_fields, list)
                casted_fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None
            self._in_form = False


def _normalize_url(url: str) -> str:
    split = urlsplit(url)
    clean_query = urlencode(sorted(parse_qsl(split.query, keep_blank_values=True)), doseq=True)
    normalized_path = split.path or "/"
    return urlunsplit((split.scheme.lower(), split.netloc.lower(), normalized_path, clean_query, ""))


def request_url(url: str, timeout: float, method: str = "GET", data: dict[str, str] | None = None) -> HTTPResponse:
    encoded_data = None
    if data is not None:
        encoded_data = urlencode(data).encode("utf-8")
    req = Request(url=url, data=encoded_data, method=method.upper(), headers={"User-Agent": "XSSpectre/0.1"})
    start = perf_counter()
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        status = resp.status
    return HTTPResponse(status=status, body=body, elapsed=perf_counter() - start)


def crawl_and_discover(start_url: str, depth: int, timeout: float) -> list[InjectionPoint]:
    visited: set[str] = set()
    frontier = {start_url}
    findings: set[InjectionPoint] = set()

    for _ in range(max(depth, 1)):
        next_frontier: set[str] = set()
        for url in frontier:
            normalized = _normalize_url(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            try:
                response = request_url(url, timeout=timeout)
            except Exception:
                continue

            parser = _DiscoveryParser(base_url=url)
            parser.feed(response.body)

            split = urlsplit(url)
            for key, _ in parse_qsl(split.query, keep_blank_values=True):
                findings.add(
                    InjectionPoint(
                        method="GET",
                        url=_normalize_url(urlunsplit((split.scheme, split.netloc, split.path, "", ""))),
                        parameter=key,
                        source="query",
                    )
                )

            for form in parser.forms:
                action = _normalize_url(str(form["action"]))
                method = str(form["method"]).upper()
                fields = tuple(sorted(set(str(x) for x in form["fields"] if x)))
                for field_name in fields:
                    findings.add(
                        InjectionPoint(
                            method=method,
                            url=action,
                            parameter=field_name,
                            source="form",
                            form_fields=fields,
                        )
                    )

            for link in parser.links:
                if urlsplit(link).netloc == split.netloc:
                    next_frontier.add(link)

        frontier = next_frontier

    return sorted(findings, key=lambda item: (item.url, item.method, item.parameter, item.source))
