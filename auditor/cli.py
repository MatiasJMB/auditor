from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import build_findings
from .crawler import Crawler
from .http_client import UA_PROFILES, SafeHttpClient
from .models import AuditConfig, AuditReport
from .reporting import write_report
from .scope import (
    AuthorizationError,
    effective_limits,
    host_from_url,
    normalize_url,
    require_authorized,
)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-scope":
            return validate_scope(args)
        if args.command == "inventory":
            return run_audit(args, include_active_checks=False)
        if args.command == "run":
            return run_audit(args, include_active_checks=True)
        parser.print_help()
        return 1
    except AuthorizationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrumpido por usuario.", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Auditoria defensiva de endpoints, exposicion de datos y scrapeabilidad.",
    )
    sub = parser.add_subparsers(dest="command")

    validate = sub.add_parser("validate-scope", help="Valida si una URL esta autorizada")
    validate.add_argument("url")
    validate.add_argument("--auth-file", default="authorized_targets.yaml")

    for command, help_text in (
        ("inventory", "Genera inventario de superficie publica"),
        ("run", "Genera inventario y checks defensivos"),
    ):
        audit = sub.add_parser(command, help=help_text)
        audit.add_argument("url")
        audit.add_argument("--out", default="reports/audit")
        audit.add_argument("--auth-file", default="authorized_targets.yaml")
        audit.add_argument("--depth", type=int, default=2)
        audit.add_argument("--max-pages", type=int, default=100)
        audit.add_argument("--timeout", type=float, default=10.0)
        audit.add_argument(
            "--rate-limit",
            type=float,
            default=1.0,
            help="Segundos minimos entre requests. 1.0 por defecto.",
        )
        audit.add_argument(
            "--profile",
            choices=["passive", "active-safe"],
            default="active-safe" if command == "run" else "passive",
        )
        audit.add_argument(
            "--ua-profile",
            choices=sorted(UA_PROFILES),
            default="auditor",
            help="Perfil de User-Agent para el crawler (auditor por defecto).",
        )
        audit.add_argument(
            "--user-agent",
            default=None,
            help="User-Agent explicito; tiene prioridad sobre --ua-profile.",
        )
        audit.add_argument(
            "--cloak-check",
            action=argparse.BooleanOptionalAction,
            default=(command == "run"),
            help=(
                "Compara la URL inicial con varios User-Agent para detectar "
                "cloaking y gates JS/cookie. Activado por defecto en 'run'."
            ),
        )

    return parser


def validate_scope(args: argparse.Namespace) -> int:
    url = normalize_url(args.url)
    target = require_authorized(url, args.auth_file)
    print(f"Autorizado: {url}")
    print(f"Dominio: {target.domain}")
    print(f"Subdominios: {'si' if target.allow_subdomains else 'no'}")
    print(f"Limites: depth={target.max_depth}, max_pages={target.max_pages}")
    return 0


def run_audit(args: argparse.Namespace, include_active_checks: bool) -> int:
    url = normalize_url(args.url)
    target = require_authorized(url, args.auth_file)
    depth, max_pages, limit_notes = effective_limits(args.depth, args.max_pages, target)
    host = host_from_url(url)

    user_agent = args.user_agent or UA_PROFILES[args.ua_profile]
    client = SafeHttpClient(
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        user_agent=user_agent,
    )
    crawler = Crawler(
        client=client,
        target=target,
        max_pages=max_pages,
        max_depth=depth,
    )
    crawl = crawler.crawl(url)
    findings = build_findings(
        start_url=url,
        target=target,
        crawl=crawl,
        client=client,
        include_active_checks=include_active_checks and args.profile == "active-safe",
        include_cloak_check=args.cloak_check,
    )

    config = AuditConfig(
        url=url,
        host=host,
        profile=args.profile,
        depth=depth,
        max_pages=max_pages,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        allow_subdomains=target.allow_subdomains,
        auth_file=str(Path(args.auth_file)),
    )
    report = AuditReport(
        target={
            "url": url,
            "host": host,
            "authorized_domain": target.domain,
            "authorization_notes": target.notes,
        },
        config=config,
        inventory=crawl.to_inventory(),
        findings=findings,
        metadata={
            "limit_notes": limit_notes,
            "active_checks": include_active_checks and args.profile == "active-safe",
            "cloak_check": args.cloak_check,
            "ua_profile": args.ua_profile,
            "user_agent": user_agent,
            "requests_recorded": len(crawl.pages),
        },
    )
    json_path, html_path = write_report(report, args.out)
    print(f"Reporte JSON: {json_path}")
    print(f"Reporte HTML: {html_path}")
    print(f"Paginas: {len(crawl.pages)}")
    print(f"Endpoints: {len(crawl.endpoints)}")
    print(f"Hallazgos: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

