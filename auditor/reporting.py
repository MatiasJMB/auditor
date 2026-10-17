from __future__ import annotations

import json
from html import escape
from pathlib import Path

from .models import AuditReport


def write_report(report: AuditReport, out_dir: str | Path) -> tuple[Path, Path]:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "audit.json"
    html_path = output / "index.html"
    data = report.to_dict()
    json_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    html_path.write_text(render_html(data), encoding="utf-8")
    return json_path, html_path


def render_html(data: dict[str, object]) -> str:
    findings = list(data.get("findings", []))
    inventory = dict(data.get("inventory", {}))
    target = dict(data.get("target", {}))
    config = dict(data.get("config", {}))

    severity_counts = _severity_counts(findings)
    findings_html = "\n".join(_finding_card(finding) for finding in findings)
    endpoints_html = _table(
        ["Metodo", "Status", "Content-Type", "Fuente", "URL"],
        [
            [
                endpoint.get("method", ""),
                endpoint.get("status_code", ""),
                endpoint.get("content_type", ""),
                endpoint.get("source", ""),
                endpoint.get("url", ""),
            ]
            for endpoint in inventory.get("endpoints", [])[:300]
        ],
    )
    visible_html = _table(
        ["Tipo", "Valor", "URL"],
        [
            [item.get("data_type", ""), item.get("value", ""), item.get("url", "")]
            for item in inventory.get("visible_data", [])[:300]
        ],
    )
    patterns_html = _patterns(inventory.get("scrape_patterns", {}))

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reporte de Auditoria Web</title>
  <style>
    :root {{ color-scheme: light; --bg: #f6f7f9; --ink: #20242a; --muted: #5d6673; --line: #d9dee7; --panel: #fff; --high: #b42318; --medium: #b54708; --low: #175cd3; --info: #475467; }}
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.45; }}
    header {{ background: #111827; color: white; padding: 28px 36px; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    section {{ margin: 0 0 28px; }}
    .meta, .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .stat, .finding, .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
    .stat strong {{ display: block; font-size: 28px; }}
    .muted {{ color: var(--muted); }}
    .severity-high {{ border-left: 5px solid var(--high); }}
    .severity-medium {{ border-left: 5px solid var(--medium); }}
    .severity-low {{ border-left: 5px solid var(--low); }}
    .severity-info {{ border-left: 5px solid var(--info); }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eef2f7; color: #344054; font-size: 12px; margin-right: 6px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 9px 10px; text-align: left; vertical-align: top; font-size: 14px; word-break: break-word; }}
    th {{ background: #eef2f7; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
  </style>
</head>
<body>
  <header>
    <h1>Reporte de Auditoria Web</h1>
    <div>{escape(str(target.get("url", "")))}</div>
    <div class="muted">Generado: {escape(str(data.get("generated_at", "")))}</div>
  </header>
  <main>
    <section class="grid">
      <div class="stat"><strong>{severity_counts.get("high", 0)}</strong><span>Altas</span></div>
      <div class="stat"><strong>{severity_counts.get("medium", 0)}</strong><span>Medias</span></div>
      <div class="stat"><strong>{severity_counts.get("low", 0)}</strong><span>Bajas</span></div>
      <div class="stat"><strong>{severity_counts.get("info", 0)}</strong><span>Informativas</span></div>
    </section>

    <section class="panel">
      <h2>Resumen</h2>
      <div class="meta">
        <div><span class="muted">Host</span><br><code>{escape(str(target.get("host", "")))}</code></div>
        <div><span class="muted">Perfil</span><br><code>{escape(str(config.get("profile", "")))}</code></div>
        <div><span class="muted">Paginas</span><br><code>{len(inventory.get("pages", []))}</code></div>
        <div><span class="muted">Endpoints</span><br><code>{len(inventory.get("endpoints", []))}</code></div>
        <div><span class="muted">Formularios</span><br><code>{len(inventory.get("forms", []))}</code></div>
        <div><span class="muted">Datos visibles</span><br><code>{len(inventory.get("visible_data", []))}</code></div>
      </div>
    </section>

    <section>
      <h2>Hallazgos</h2>
      {findings_html or '<div class="panel">No se registraron hallazgos.</div>'}
    </section>

    <section>
      <h2>Scrapeabilidad</h2>
      {patterns_html}
    </section>

    <section>
      <h2>Endpoints</h2>
      {endpoints_html}
    </section>

    <section>
      <h2>Informacion Visible</h2>
      {visible_html}
    </section>
  </main>
</body>
</html>"""


def _severity_counts(findings: list[object]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if isinstance(finding, dict):
            severity = str(finding.get("severity", "info"))
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def _finding_card(finding: object) -> str:
    if not isinstance(finding, dict):
        return ""
    severity = escape(str(finding.get("severity", "info")))
    title = escape(str(finding.get("title", "")))
    url = escape(str(finding.get("url", "")))
    evidence = escape(str(finding.get("evidence", "")))
    risk = escape(str(finding.get("risk", "")))
    recommendation = escape(str(finding.get("recommendation", "")))
    category = escape(str(finding.get("category", "")))
    confidence = escape(str(finding.get("confidence", "")))
    return f"""
      <article class="finding severity-{severity}">
        <h3>{title}</h3>
        <p><span class="badge">{severity}</span><span class="badge">{category}</span><span class="badge">{confidence}</span></p>
        <p><strong>URL:</strong> <code>{url}</code></p>
        <p><strong>Evidencia:</strong> {evidence}</p>
        <p><strong>Riesgo:</strong> {risk}</p>
        <p><strong>Recomendacion:</strong> {recommendation}</p>
      </article>
    """


def _table(headers: list[str], rows: list[list[object]]) -> str:
    if not rows:
        return '<div class="panel">Sin datos.</div>'
    head = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body = "\n".join(
        "<tr>"
        + "".join(f"<td>{escape(str(cell))}</td>" for cell in row)
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _patterns(patterns: object) -> str:
    if not isinstance(patterns, dict) or not patterns:
        return '<div class="panel">No se detectaron patrones relevantes.</div>'
    rows: list[list[object]] = []
    for name, urls in patterns.items():
        if isinstance(urls, list):
            rows.append([name, len(urls), "\n".join(str(url) for url in urls[:10])])
    return _table(["Patron", "Cantidad", "Ejemplos"], rows)

