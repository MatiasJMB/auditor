from unittest import TestCase

from auditor.checks import check_cors, check_headers_and_cookies, check_scrapeability
from auditor.crawler import CrawlResult
from auditor.models import PageRecord, VisibleData


class CheckTests(TestCase):
    def test_missing_headers_create_findings(self) -> None:
        crawl = CrawlResult(
            pages=[
                PageRecord(
                    url="https://example.com",
                    final_url="https://example.com",
                    status_code=200,
                    content_type="text/html",
                    headers={},
                )
            ]
        )
        findings = check_headers_and_cookies(crawl)
        titles = {finding.title for finding in findings}
        self.assertIn("HSTS ausente", titles)
        self.assertIn("CSP ausente", titles)

    def test_cors_wildcard(self) -> None:
        crawl = CrawlResult(
            pages=[
                PageRecord(
                    url="https://example.com/api",
                    final_url="https://example.com/api",
                    status_code=200,
                    content_type="application/json",
                    headers={"access-control-allow-origin": "*"},
                )
            ]
        )
        findings = check_cors(crawl)
        self.assertEqual(findings[0].title, "CORS permisivo")

    def test_scrapeability_visible_data(self) -> None:
        crawl = CrawlResult(
            visible_data=[
                VisibleData(url="https://example.com", data_type="email", value="a@example.com")
            ],
            scrape_patterns={"api_like": ["https://example.com/api/items"]},
        )
        findings = check_scrapeability(crawl)
        titles = {finding.title for finding in findings}
        self.assertIn("Endpoints API publicos detectados", titles)
        self.assertIn("Emails scrapeables detectados", titles)

