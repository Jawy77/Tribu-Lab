"""Lenguajes y cobertura de SAST: el gate no puede dar un verde enganoso."""
import subprocess
from pathlib import Path

import pytest

from auditgate import languages, scan


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def poly(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.name", "t")
    git(r, "config", "user.email", "t@t")
    (r / "README.md").write_text("x\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "checkout", "-q", "-b", "feature")
    for path, body in {
        "svc/app.py": "x = 1\n", "svc/util.py": "y = 2\n", "web/a.ts": "let a = 1\n",
        "api/main.go": "package main\n", "mobile/main.dart": "void main() {}\n",
        "node_modules/x/i.js": "1\n", "rules/mine.py": "bad = 1\n",
    }.items():
        f = r / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    git(r, "add", "-A", "-f")
    git(r, "commit", "-qm", "code")
    return r


def test_detect_counts_and_skips_vendored_and_fixtures(poly):
    assert languages.detect(poly) == {"python": 2, "dart": 1, "go": 1, "typescript": 1}


def test_plan_covers_each_language_and_flags_uncovered(poly):
    plan = languages.sast_plan(poly, use_registry=True)
    assert plan["coverage"]["python"] == ["reglas propias", "p/python"]
    assert plan["coverage"]["typescript"] == ["reglas propias", "p/typescript"]
    assert plan["coverage"]["go"] == ["p/golang"]
    assert plan["uncovered"] == ["dart"]
    assert "p/golang" in plan["configs"] and "p/javascript" not in plan["configs"]  # solo lo detectado
    assert not any(c.endswith("github-actions") for c in plan["configs"])


def test_without_registry_only_own_rules_cover(poly):
    plan = languages.sast_plan(poly, use_registry=False)
    assert sorted(plan["uncovered"]) == ["dart", "go"]
    assert not any(c.startswith("p/") for c in plan["configs"])


def test_repo_own_rules_extend_coverage(poly):
    rules = poly / "rules"
    (rules / "go.yml").write_text("rules:\n  - id: x\n    languages: [go]\n    severity: ERROR\n    message: m\n    pattern: f()\n")
    plan = languages.sast_plan(poly, use_registry=False)
    assert plan["coverage"]["go"] == ["reglas propias"]
    assert str(rules) in plan["configs"]


def test_summary_warns_about_uncovered(poly):
    text = languages.render_summary(languages.sast_plan(poly))
    assert "sin cobertura" in text and "dart" in text


def test_scan_reports_coverage_and_strict_fails_on_uncovered(poly, monkeypatch):
    real_run = subprocess.run

    def fake_run(cmd, **kw):
        if cmd[0] == "semgrep":
            return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "errors": []}', stderr="")
        return real_run(cmd, **kw)

    monkeypatch.setattr(scan.shutil, "which", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    report = scan.run_scan(poly, base="main", checks=("sast",))
    assert report["gate"] == "passed"  # no bloquea, pero lo dice
    assert report["uncovered_languages"] == ["dart"]
    assert "SIN COBERTURA: dart" in report["checks"][0]["detail"]
    assert "SAST no revisó código en: dart" in scan.render_text(report)
    strict = scan.run_scan(poly, base="main", checks=("sast",), strict=True)
    assert strict["gate"] == "error" and scan.exit_code(strict) == 2
