"""`auditgate scan`: politica, codigos de salida, worktree y salida para agentes (sin red)."""
import json
import subprocess
from pathlib import Path

import pytest

from auditgate import scan

PINNED = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.name", "t")
    git(r, "config", "user.email", "t@t")
    (r / "README.md").write_text("x\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "checkout", "-q", "-b", "feature")
    return r


def commit_workflow(repo: Path, ref: str) -> None:
    wf = repo / ".github/workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {ref}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "wf")


def test_unpinned_action_blocks_and_can_be_report_only(repo):
    commit_workflow(repo, "actions/checkout@v4")
    report = scan.run_scan(repo, base="main", checks=("actions",))
    assert report["gate"] == "blocked" and scan.exit_code(report) == 1
    assert report["checks"][0]["findings"][0]["path"] == ".github/workflows/ci.yml"
    relaxed = scan.run_scan(repo, base="main", checks=("actions",), enforce_pins=False)
    assert relaxed["gate"] == "passed" and scan.exit_code(relaxed) == 0


def test_pinned_action_passes(repo):
    commit_workflow(repo, PINNED)
    assert scan.run_scan(repo, base="main", checks=("actions",))["gate"] == "passed"


def test_worktree_is_cleaned_and_uncommitted_is_flagged(repo):
    (repo / "wip.txt").write_text("sin commit\n")
    report = scan.run_scan(repo, base="main", checks=("actions",))
    assert report["uncommitted_changes"] is True
    assert len(git(repo, "worktree", "list").splitlines()) == 1  # solo el principal
    assert (repo / "wip.txt").read_text() == "sin commit\n"  # nunca toca tu trabajo


def test_missing_tool_is_skipped_or_error_in_strict(repo, monkeypatch):
    monkeypatch.setattr(scan, "find_tool", lambda _: None)
    report = scan.run_scan(repo, base="main", checks=("secrets", "sast"))
    assert [c["status"] for c in report["checks"]] == ["skipped", "skipped"]
    assert "auditgate setup" in report["checks"][1]["detail"]
    assert report["gate"] == "passed"
    strict = scan.run_scan(repo, base="main", checks=("secrets",), strict=True)
    assert strict["gate"] == "error" and scan.exit_code(strict) == 2


def test_unknown_base_is_config_error(repo):
    with pytest.raises(scan.ScanError):
        scan.run_scan(repo, base="no-existe", checks=("actions",))


def test_sast_normalizes_rule_ids_and_skips_actions_rules(repo, monkeypatch):
    git(repo, "commit", "--allow-empty", "-qm", "c")
    seen = {}
    fake = {"results": [
        {"check_id": "private.tmp.x.auditgate.rules.python.auditgate.flask.sqli-string-built-query",
         "path": "app/api.py", "start": {"line": 9}, "extra": {"message": "SQLi"}},
        {"check_id": "python.flask.security.injection.tainted-sql-string.tainted-sql-string",
         "path": "app/api.py", "start": {"line": 9}, "extra": {"message": "taint"}},
    ], "errors": []}
    real_run = subprocess.run

    def fake_run(cmd, **kw):
        if Path(cmd[0]).name == "opengrep":
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(fake), stderr="")
        return real_run(cmd, **kw)

    monkeypatch.setattr(scan, "find_tool", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    report = scan.run_scan(repo, base="main", checks=("sast",))
    assert report["checks"][0]["tool"] == "opengrep"
    assert "--metrics=off" not in seen["cmd"]  # opengrep no tiene telemetria ni esa opcion
    rules = [f["rule"] for f in report["checks"][0]["findings"]]
    assert rules == ["auditgate.flask.sqli-string-built-query",
                     "python.flask.security.injection.tainted-sql-string.tainted-sql-string"]
    configs = [seen["cmd"][i + 1] for i, a in enumerate(seen["cmd"]) if a == "--config"]
    assert not any(c.endswith("github-actions") for c in configs)  # lo cubre el check `actions`
    assert "--baseline-commit" in seen["cmd"]
    assert report["gate"] == "blocked"


def test_json_contract_for_agents(repo):
    commit_workflow(repo, PINNED)
    report = scan.run_scan(repo, base="main", checks=("actions",))
    assert set(report) >= {"auditgate_version", "gate", "base", "head", "uncommitted_changes", "checks", "summary"}
    json.dumps(report)  # serializable
    text = scan.render_text(report)
    assert "Auditgate scan" in text and "✅ Pasa" in text


def test_cli_exit_codes(repo, monkeypatch, capsys):
    from auditgate import cli

    commit_workflow(repo, "actions/checkout@v4")
    monkeypatch.chdir(repo)
    assert cli.main(["scan", "--base", "main", "--checks", "actions", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["gate"] == "blocked"
    assert cli.main(["scan", "--base", "main", "--checks", "nope"]) == 2
    assert cli.main(["scan", "--base", "no-existe", "--checks", "actions", "--json"]) == 2


def test_semgrep_is_used_as_fallback_engine_with_metrics_off(repo, monkeypatch):
    git(repo, "commit", "--allow-empty", "-qm", "c")
    seen = {}
    real_run = subprocess.run

    def fake_run(cmd, **kw):
        if Path(cmd[0]).name == "semgrep":
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "errors": []}', stderr="")
        return real_run(cmd, **kw)

    monkeypatch.setattr(scan, "find_tool", lambda t: None if t == "opengrep" else f"/usr/bin/{t}")
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    report = scan.run_scan(repo, base="main", checks=("sast",))
    assert report["checks"][0]["tool"] == "semgrep" and "--metrics=off" in seen["cmd"]
