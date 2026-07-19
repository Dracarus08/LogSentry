"""Renders a Digest as plain text or as a self-contained HTML page."""

from __future__ import annotations

from html import escape

from .engine import Digest


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
    total_inc = len(digest.findings)
    bar_total = max(digest.high + digest.medium + digest.low, 1)
    hi_w = round(digest.high / bar_total * 100, 2)
    med_w = round(digest.medium / bar_total * 100, 2)
    low_w = round(digest.low / bar_total * 100, 2)
    if digest.high:
        noun = "incident needs" if digest.high == 1 else "incidents need"
        verdict = f"{digest.high} high-severity {noun} review."
    elif digest.findings:
        verdict = "No high-severity incidents."
    else:
        verdict = "No incidents in this window."

    incidents_html = []
    if digest.findings:
        for f in digest.findings:
            sev = f.severity.lower()
            when = f.when.strftime("%Y-%m-%d %H:%M") if f.when else ""
            attack = (
                f'<span class="attck">{escape(", ".join(f.attack))}</span>'
                if f.attack else ""
            )
            evidence = "".join(f"<li>{escape(ev)}</li>" for ev in f.evidence)
            incidents_html.append(
                f'<div class="inc">'
                f'<div class="inc-h">'
                f'<span class="sev sev-{sev}"><span class="sq bg-{sev}"></span>'
                f"{escape(f.severity)}</span>"
                f'<span class="inc-t">{escape(f.title)}</span>'
                f'<span class="when">{escape(when)}</span>'
                f"</div>"
                f'<p class="detail">{escape(f.detail)} {attack}</p>'
                f'<ul class="evidence">{evidence}</ul>'
                f"</div>"
            )
    else:
        incidents_html.append('<div class="clean">No incidents detected in this window.</div>')

    sources_rows = "".join(
        f'<tr><td class="fig">{count}</td><td>{escape(ip)}</td></tr>'
        for ip, count in digest.top_sources
    )
    sources_html = (
        "<h2>Top sources of failed authentication</h2>"
        '<table class="sources"><thead><tr><th>Failures</th><th>Source</th></tr></thead>'
        f"<tbody>{sources_rows}</tbody></table>"
        if digest.top_sources else ""
    )

    hosts = escape(", ".join(digest.hosts) if digest.hosts else "none")
    return _PAGE.format(
        range_label=escape(_range_label(digest)),
        hosts=hosts,
        total=len(digest.events),
        incidents_total=total_inc,
        verdict=escape(verdict),
        high=digest.high,
        medium=digest.medium,
        low=digest.low,
        hi_w=hi_w,
        med_w=med_w,
        low_w=low_w,
        failed=digest.failed_auths,
        lockouts=digest.lockouts,
        privilege=digest.privilege_events,
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
<title>Security Log Digest</title>
<style>
  :root {{
    --paper: #f4f1ea; --ink: #1c1b18; --muted: #6a655c; --faint: #938d81;
    --rule: #d8d1c3; --rule-soft: #e5e0d5;
    --high: #a3302c; --med: #9a7220; --low: #4a6884; --ok: #3f7048;
    --serif: Georgia, 'Iowan Old Style', 'Times New Roman', serif;
    --sans: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Mono', 'Consolas', 'DejaVu Sans Mono', monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: var(--sans); margin: 0; background: var(--paper); color: var(--ink); -webkit-font-smoothing: antialiased; }}
  .sheet {{ max-width: 940px; margin: 0 auto; padding: 52px 56px 72px; }}

  .wordmark {{ font-family: var(--mono); font-size: 11.5px; letter-spacing: 2.5px; text-transform: uppercase; color: var(--muted); }}
  .wordmark b {{ color: var(--high); font-weight: 700; }}
  h1 {{ font-family: var(--serif); font-weight: 600; font-size: 31px; letter-spacing: -0.2px; margin: 6px 0 10px; }}
  .meta {{ font-family: var(--mono); font-size: 12px; color: var(--muted); letter-spacing: .2px; }}
  .rule-strong {{ border: none; border-top: 2px solid var(--ink); margin: 18px 0 0; }}

  .summary {{ display: grid; grid-template-columns: 200px 1fr; gap: 40px; padding: 30px 0 6px; align-items: start; }}
  .p-score {{ font-family: var(--serif); font-size: 56px; line-height: 1; font-weight: 600; }}
  .p-label {{ font-family: var(--mono); text-transform: uppercase; letter-spacing: 2px; font-size: 10.5px; color: var(--muted); margin-top: 8px; }}
  .p-verdict {{ font-family: var(--serif); font-style: italic; font-size: 15px; color: var(--ink); margin-top: 12px; max-width: 220px; }}

  .dist-head {{ display: flex; gap: 26px; font-family: var(--mono); font-size: 12px; color: var(--muted); margin-bottom: 10px; }}
  .dist-head .n {{ color: var(--ink); font-weight: 700; }}
  .dist-head .sq {{ display: inline-block; width: 9px; height: 9px; margin-right: 6px; }}
  .bar {{ display: flex; height: 8px; width: 100%; overflow: hidden; border: 1px solid var(--rule); }}
  .bar span {{ display: block; height: 100%; }}
  .telemetry {{ font-family: var(--mono); font-size: 11.5px; color: var(--faint); margin-top: 10px; }}

  h2 {{ font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: 2px; color: var(--muted); font-weight: 400; margin: 40px 0 0; padding-bottom: 8px; }}
  .incidents {{ margin-top: 8px; }}
  .inc {{ padding: 22px 0 6px; border-top: 1px solid var(--rule); }}
  .inc:first-child {{ border-top: 2px solid var(--ink); }}
  .inc-h {{ display: flex; align-items: baseline; gap: 14px; }}
  .sev {{ white-space: nowrap; font-weight: 700; font-family: var(--mono); font-size: 11.5px; letter-spacing: .5px; text-transform: uppercase; min-width: 74px; }}
  .sev .sq {{ display: inline-block; width: 8px; height: 8px; margin-right: 7px; }}
  .sev-high {{ color: var(--high); }} .sev-medium {{ color: var(--med); }} .sev-low {{ color: var(--low); }}
  .bg-high {{ background: var(--high); }} .bg-medium {{ background: var(--med); }} .bg-low {{ background: var(--low); }}
  .inc-t {{ font-weight: 600; font-size: 15.5px; flex: 1; }}
  .when {{ font-family: var(--mono); color: var(--faint); font-size: 11.5px; }}
  .detail {{ color: var(--muted); font-size: 13.5px; margin: 8px 0 8px 88px; line-height: 1.5; }}
  .attck {{ font-family: var(--mono); font-size: 11px; color: var(--faint); letter-spacing: .5px; }}
  .evidence {{ list-style: none; margin: 0 0 4px 88px; padding: 6px 0 6px 14px; border-left: 2px solid var(--rule); color: var(--muted); font-size: 12px; font-family: var(--mono); line-height: 1.7; }}
  .clean {{ margin: 12px 0; font-family: var(--mono); font-size: 12.5px; color: var(--ok); }}

  table.sources {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-family: var(--mono); font-size: 12.5px; max-width: 360px; }}
  table.sources th {{ text-align: left; padding: 6px 16px 8px 0; color: var(--muted); font-weight: 400; font-size: 10.5px; text-transform: uppercase; letter-spacing: 1.5px; border-bottom: 1px solid var(--rule); }}
  table.sources td {{ padding: 6px 16px 6px 0; border-bottom: 1px solid var(--rule-soft); }}
  table.sources .fig {{ color: var(--high); font-weight: 700; }}

  footer {{ margin-top: 44px; padding-top: 14px; border-top: 1px solid var(--rule); font-family: var(--mono); font-size: 11px; color: var(--faint); letter-spacing: .3px; }}
</style>
</head>
<body>
<div class="sheet">
<header>
  <div class="wordmark">LogSentry <b>&bull;</b> v1.0.0</div>
  <h1>Security Log Digest</h1>
  <div class="meta">{range_label} &nbsp;&middot;&nbsp; {hosts} &nbsp;&middot;&nbsp; {total} events</div>
  <hr class="rule-strong">
</header>

<section class="summary">
  <div>
    <div class="p-score">{incidents_total}</div>
    <div class="p-label">Incidents</div>
    <div class="p-verdict">{verdict}</div>
  </div>
  <div>
    <div class="dist-head">
      <span><span class="sq bg-high"></span>High <span class="n">{high}</span></span>
      <span><span class="sq bg-medium"></span>Medium <span class="n">{medium}</span></span>
      <span><span class="sq bg-low"></span>Low <span class="n">{low}</span></span>
    </div>
    <div class="bar">
      <span class="bg-high" style="width:{hi_w}%"></span>
      <span class="bg-medium" style="width:{med_w}%"></span>
      <span class="bg-low" style="width:{low_w}%"></span>
    </div>
    <div class="telemetry">failed auth {failed} &middot; lockouts {lockouts} &middot; privilege grants {privilege}</div>
  </div>
</section>

<h2>Incidents</h2>
<div class="incidents">{incidents}</div>
{sources}
<footer>LogSentry v1.0.0 &middot; source-agnostic detection &middot; synthetic demonstration data &middot; no production logs were used</footer>
</div>
</body>
</html>
"""
