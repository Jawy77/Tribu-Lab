"""CLI: la llave nunca va en argv, el workflow generado es valido y se detecta el proyecto."""
import subprocess
from pathlib import Path

import pytest

from auditgate_cli import main as cli

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def test_key_goes_through_stdin_never_argv(monkeypatch):
    calls = []

    def fake_run(argv, input=None, capture_output=True, text=True):
        calls.append({"argv": argv, "input": input})
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli.store_key("o/r", "sk-SUPER-SECRET")
    assert calls[0]["argv"][:4] == ["gh", "api", "-X", "PUT"]
    assert calls[0]["argv"][4] == "repos/o/r/environments/auditgate"
    secret_call = calls[1]
    assert secret_call["argv"] == ["gh", "secret", "set", "AUDITGATE_LLM_API_KEY", "--env", "auditgate", "--repo", "o/r"]
    assert secret_call["input"] == "sk-SUPER-SECRET"
    assert all("sk-SUPER-SECRET" not in " ".join(c["argv"]) for c in calls)


def test_gh_error_never_echoes_the_key(monkeypatch):
    def fake_run(argv, input=None, capture_output=True, text=True):
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="HTTP 403")

    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as exc:
        cli.gh("secret", "set", "X", input_text="sk-SUPER-SECRET")
    assert "sk-SUPER-SECRET" not in str(exc.value)


def test_read_key_rejects_empty_and_spaces(monkeypatch):
    import io

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("   "))
    with pytest.raises(SystemExit):
        cli.read_key(from_stdin=True)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("sk-abc def"))
    with pytest.raises(SystemExit):
        cli.read_key(from_stdin=True)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("sk-abc\n"))
    assert cli.read_key(from_stdin=True) == "sk-abc"


def test_detect_project_and_unpinned(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask==3.1.3\n")
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc/requirements-dev.txt").write_text("pytest\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/requirements.txt").write_text("x\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra/main.tf").write_text("")
    wf = tmp_path / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        f"steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-python@{SHA} # v7\n  - uses: ./local\n"
    )
    project = cli.detect_project(tmp_path)
    assert project == {"requirements": "requirements.txt svc/requirements-dev.txt",
                       "dockerfile": "Dockerfile", "iac_dir": "infra"}
    hits = cli.unpinned_actions(tmp_path)
    assert len(hits) == 1 and "actions/checkout@v4" in hits[0]


def test_rendered_workflow_pins_both_refs():
    out = cli.render_workflow(SHA, "v0.1.0", {"requirements": "requirements.txt", "dockerfile": "", "iac_dir": ""}, True)
    assert f"security-platform.yml@{SHA} # v0.1.0" in out
    assert f"platform-ref: {SHA}" in out
    assert "${{ vars.AUDITGATE_LLM_PROVIDER }}" in out
    assert "AUDITGATE_LLM_API_KEY" not in out  # la llave nunca se escribe en el repo
