from unittest import TestCase

from auditor.extractors import (
    detect_scrape_patterns,
    extract_js_endpoints,
    extract_visible_data,
    parse_html,
)


class ExtractorTests(TestCase):
    def test_parse_html_links_forms_and_scripts(self) -> None:
        parsed = parse_html(
            "https://example.com/base/",
            """
            <html><head><title>Demo</title><script src="/app.js"></script></head>
            <body>
              <a href="/api/items?page=1">Items</a>
              <form action="/search" method="post"><input name="q"></form>
            </body></html>
            """,
        )
        self.assertEqual(parsed.title, "Demo")
        self.assertIn("https://example.com/api/items?page=1", parsed.links)
        self.assertIn("https://example.com/app.js", parsed.scripts)
        self.assertEqual(parsed.forms[0].action, "https://example.com/search")
        self.assertEqual(parsed.forms[0].fields, ["q"])

    def test_extract_js_endpoints(self) -> None:
        endpoints = extract_js_endpoints(
            "https://example.com/static/app.js",
            "fetch('/api/users?limit=10'); const url='https://example.com/graphql';",
        )
        self.assertIn("https://example.com/api/users?limit=10", endpoints)
        self.assertIn("https://example.com/graphql", endpoints)

    def test_extract_visible_data_sanitizes_secret(self) -> None:
        items = extract_visible_data(
            "https://example.com",
            "Contact test@example.com api_key='abcd1234abcd1234abcd1234' http://localhost:8000",
        )
        values = [item.value for item in items]
        self.assertIn("test@example.com", values)
        self.assertTrue(any("abcd...1234" in value for value in values))

    def test_detect_scrape_patterns(self) -> None:
        patterns = detect_scrape_patterns(
            [
                "https://example.com/api/items?page=1",
                "https://example.com/search?q=test",
                "https://example.com/file.pdf",
            ]
        )
        self.assertEqual(len(patterns["pagination"]), 1)
        self.assertEqual(len(patterns["search_or_filter"]), 1)
        self.assertEqual(len(patterns["downloadable_documents"]), 1)
        self.assertEqual(len(patterns["api_like"]), 1)

