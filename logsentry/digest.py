"""Renders a Digest as plain text or as a self-contained HTML page."""

from __future__ import annotations

from html import escape

from .engine import Digest

_SEV_COLOR = {"High": "#e5484d", "Medium": "#f5a623", "Low": "#4a90d9"}


def render_text(digest: Digest) -> str:
    lines: list[str] = []
    rng = _range_label(digest)
    lines.append("LogSentry Daily Digest")
    lines.append(rng)
    hosts = ", ".join(digest.hosts) if digest.hosts else "none"
    lines.append(f"Hosts: {hosts}")
    lines.append("")
    lines.append(
        f"Events {len(digest.events)}  Failed auth {digest.failed_auths}  "
        f"Lockouts {digest.lockouts}  Privilege {digest.privilege_events}"
    )
    lines.append(
        f"Incidents  High {digest.high}  Medium {digest.medium}  Low {digest.low}"
    )
    lines.append("")

    if digest.findings:
        lines.append("Incidents")
        lines.append("-" * 60)
        for f in digest.findings:
            when = f.when.strftime("%Y-%m-%d %H:%M") if f.when else ""
            lines.append(f"[{f.severity}] {f.title}  ({when})")
            lines.append(f"    {f.detail}")
            if f.attack:
                lines.append(f"    ATT&CK: {', '.join(f.attack)}")
            for ev in f.evidence:
                lines.append(f"      - {ev}")
            lines.append("")
    else:
        lines.append("No incidents detected in this window.")
        lines.append("")

    if digest.top_sources:
        lines.append("Top sources of failed authentication")
        lines.append("-" * 60)
        for ip, count in digest.top_sources:
            lines.append(f"    {count:>5}  {ip}")
    return "\n".join(lines)


def render_html(digest: Digest) -> str:
    cards = [
        ("High", digest.high, _SEV_COLOR["High"]),
        ("Medium", digest.medium, _SEV_COLOR["Medium"]),
        ("Failed auth", digest.failed_auths, "#e6e6e6"),
        ("Lockouts", digest.lockouts, "#e6e6e6"),
        ("Privilege", digest.privilege_events, "#e6e6e6"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="num" style="color:{color}">{value}</div>'
        f'<div class="lbl">{escape(label)}</div></div>'
        for label, value, color in cards
    )

    incidents_html = []
    if digest.findings:
        for f in digest.findings:
            color = _SEV_COLOR.get(f.severity, "#8a8f98")
            when = f.when.strftime("%Y-%m-%d %H:%M") if f.when else ""
            attack = (
                f'<span class="attck">ATT&amp;CK {escape(", ".join(f.attack))}</span>'
                if f.attack else ""
            )
            evidence = "".join(
                f"<li>{escape(ev)}</li>" for ev in f.evidence
            )
            incidents_html.append(
                f'<div class="inc">'
                f'<div class="inc-h"><span class="pill" style="background:{color}">'
                f'{escape(f.severity)}</span><span class="inc-t">{escape(f.title)}</span>'
                f'<span class="when">{escape(when)}</span></div>'
                f'<p class="detail">{escape(f.detail)} {attack}</p>'
                f'<ul class="evidence">{evidence}</ul>'
                f"</div>"
            )
    else:
        incidents_html.append('<div class="clean">No incidents detected in this window.</div>')

    sources_rows = "".join(
        f"<tr><td>{count}</td><td>{escape(ip)}</td></tr>"
        for ip, count in digest.top_sources
    )
    sources_html = (
        f'<h2>Top sources of failed authentication</h2>'
        f'<table><thead><tr><th>Failures</th><th>Source IP</th></tr></thead>'
        f"<tbody>{sources_rows}</tbody></table>"
        if digest.top_sources else ""
    )

    hosts = escape(", ".join(digest.hosts) if digest.hosts else "none")
    return _PAGE.format(
        range_label=escape(_range_label(digest)),
        hosts=hosts,
        total=len(digest.events),
        cards=card_html,
        incidents="".join(incidents_html),
        sources=sources_html,
    )


def _range_label(digest: Digest) -> str:
    if digest.start and digest.end:
        if digest.start.date() == digest.end.date():
            return digest.start.strftime("%Y-%m-%d")
        return f"{digest.start.strftime('%Y-%m-%d')} to {digest.end.strftime('%Y-%m-%d')}"
    return "no events"


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogSentry Digest</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; background: #0f1115; color: #e6e6e6; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ margin: 0 0 4px; font-size: 24px; }}
  .meta {{ color: #9aa0a6; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 28px; }}
  .card {{ background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 16px; }}
  .card .num {{ font-size: 30px; font-weight: 700; line-height: 1; }}
  .card .lbl {{ font-size: 12px; color: #9aa0a6; margin-top: 6px; text-transform: uppercase; letter-spacing: .5px; }}
  h2 {{ font-size: 15px; color: #b9bec5; border-bottom: 1px solid #262b36; padding-bottom: 8px; margin: 28px 0 12px; }}
  .inc {{ background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 14px 18px; margin-bottom: 12px; }}
  .inc-h {{ display: flex; align-items: center; gap: 10px; }}
  .pill {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 20px; color: #fff; }}
  .inc-t {{ font-weight: 600; }}
  .when {{ margin-left: auto; color: #7d8590; font-size: 12px; }}
  .detail {{ color: #b9bec5; font-size: 13px; margin: 10px 0 6px; }}
  .attck {{ color: #7d8590; font-size: 11px; }}
  .evidence {{ margin: 6px 0 0; padding-left: 18px; color: #8a8f98; font-size: 12px; font-family: ui-monospace, Consolas, monospace; }}
  .clean {{ color: #3fb950; padding: 12px 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #21262e; }}
  th {{ color: #9aa0a6; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }}
  footer {{ margin-top: 32px; color: #6e7681; font-size: 12px; border-top: 1px solid #262b36; padding-top: 16px; }}
</style>
</head>
<body>
<div class="wrap">
<h1>LogSentry Daily Digest</h1>
<div class="meta">Window: {range_label} &nbsp;|&nbsp; Hosts: {hosts} &nbsp;|&nbsp; {total} events</div>
<div class="cards">{cards}</div>
<h2>Incidents</h2>
{incidents}
{sources}
<footer>Generated by LogSentry. This digest is built through my automated development pipeline, designed, reviewed, and operated by me.</footer>
</div>
</body>
</html>
"""
