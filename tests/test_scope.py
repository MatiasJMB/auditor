from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from auditor.scope import AuthorizationError, load_authorized_targets, require_authorized, same_scope


class ScopeTests(TestCase):
    def test_loads_yaml_subset_and_matches_subdomain(self) -> None:
        with TemporaryDirectory() as tmp:
            auth = Path(tmp) / "authorized_targets.yaml"
            auth.write_text(
                """
targets:
  - domain: example.com
    allow_subdomains: true
    max_depth: 3
    max_pages: 25
""",
                encoding="utf-8",
            )
            targets = load_authorized_targets(auth)
            self.assertEqual(targets[0].domain, "example.com")
            self.assertTrue(same_scope("https://api.example.com/v1", targets[0]))
            self.assertEqual(require_authorized("https://www.example.com", auth).max_pages, 25)

    def test_blocks_unauthorized_domain(self) -> None:
        with TemporaryDirectory() as tmp:
            auth = Path(tmp) / "authorized_targets.yaml"
            auth.write_text(
                """
targets:
  - domain: example.com
    allow_subdomains: false
""",
                encoding="utf-8",
            )
            with self.assertRaises(AuthorizationError):
                require_authorized("https://evil.test", auth)

