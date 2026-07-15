from logsentry import engine
from logsentry.cli import build_parser, load_events, main
from logsentry.digest import render_html, render_text


def _demo_digest():
    args = build_parser().parse_args(["--demo"])
    events = load_events(args)
    return engine.run(events)


def test_demo_loads_both_sources():
    args = build_parser().parse_args(["--demo"])
    events = load_events(args)
    assert any(e.source == "windows" for e in events)
    assert any(e.source == "syslog" for e in events)


def test_demo_digest_has_expected_incidents():
    digest = _demo_digest()
    ids = {f.detection_id for f in digest.findings}
    for expected in {"BRUTE-FORCE", "SPRAY-SUCCESS", "LOCKOUT", "PRIV-GRANT",
                     "LOG-CLEARED", "OFF-HOURS-ADMIN"}:
        assert expected in ids, f"missing {expected}"
    assert digest.high >= 5


def test_render_text_and_html():
    digest = _demo_digest()
    text = render_text(digest)
    assert "LogSentry Daily Digest" in text
    html = render_html(digest)
    assert "<html" in html.lower()
    assert "Incidents" in html
    # No unescaped raw ampersands from ATT&CK in the body break the markup.
    assert "ATT&amp;CK" in html


def test_cli_writes_html(tmp_path, capsys):
    out = tmp_path / "digest.html"
    code = main(["--demo", "--out", str(out)])
    assert code == 0
    assert out.exists()
    assert "LogSentry" in out.read_text(encoding="utf-8")


def test_cli_requires_input(capsys):
    code = main([])
    assert code == 2
