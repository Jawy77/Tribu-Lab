"""
`auditgate scan` — el mismo gate del PR, en tu maquina (o en la de tu agente).

Evalua lo que va a llegar al PR: los commits entre el merge-base con `--base`
y HEAD. Corre en un `git worktree` temporal de HEAD, asi:
  - el resultado es el mismo que en CI (estado commiteado, no tu disco),
  - nunca toca tus archivos ni tus cambios sin guardar.

Politica (igual que security-platform.yml): bloquea solo lo NUEVO.
  secrets  gitleaks   secretos en los commits nuevos
  sast     semgrep    hallazgos ERROR nuevos (reglas de Auditgate + p/python + rules/ propias)
  deps     pip-audit  vulnerabilidades nuevas en requirements*.txt
  actions  auditgate  actions sin fijar por SHA en .github/workflows

Codigos de salida: 0 pasa · 1 bloqueado · 2 error de configuracion o de herramienta.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from auditgate import __version__
from auditgate.project import detect_project, unpinned_actions

RULES_DIR = Path(__file__).resolve().parent / "rules"
ALL_CHECKS = ("secrets", "sast", "deps", "actions")

INSTALL_HINTS = {
    "gitleaks": "brew install gitleaks  (o https://github.com/gitleaks/gitleaks#installing)",
    "semgrep": "pipx install semgrep",
    "pip-audit": "pipx install pip-audit",
}

EXIT_PASSED, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


class ScanError(RuntimeError):
    """Error de configuracion (no es un hallazgo): exit 2."""


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    message: str
    severity: str = "error"


@dataclass
class Check:
    id: str
    tool: str
    status: str = "passed"  # passed | blocked | skipped | error
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)


# ── git ──────────────────────────────────────────────────────────────────────
def _git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ScanError(f"git {' '.join(args)}: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def resolve_base(repo: Path, base: str | None) -> str:
    if base:
        return base
    # El default branch del remoto (origin/HEAD → origin/main), o main/master locales.
    proc = subprocess.run(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
                          cwd=repo, capture_output=True, text=True)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    for candidate in ("main", "master"):
        if subprocess.run(["git", "rev-parse", "--verify", "--quiet", candidate], cwd=repo,
                          capture_output=True).returncode == 0:
            return candidate
    raise ScanError("No pude deducir la rama base. Usa --base <rama|sha>.")


# ── checks ───────────────────────────────────────────────────────────────────
def _missing(check: Check, tool: str) -> Check:
    check.status = "skipped"
    check.detail = f"{tool} no está instalado → {INSTALL_HINTS[tool]}"
    return check


def check_secrets(wt: Path, merge_base: str, head: str) -> Check:
    check = Check("secrets", "gitleaks")
    if not shutil.which("gitleaks"):
        return _missing(check, "gitleaks")
    if merge_base == head:
        check.detail = "sin commits nuevos respecto a la base"
        return check
    report = wt / ".auditgate-gitleaks.json"
    cmd = ["gitleaks", "git", "--log-opts", f"{merge_base}..{head}", "--redact", "--no-banner",
           "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
    if (wt / ".gitleaks.toml").is_file():
        cmd += ["--config", str(wt / ".gitleaks.toml")]
    proc = subprocess.run(cmd, cwd=wt, capture_output=True, text=True)
    if proc.returncode != 0 or not report.exists():
        check.status, check.detail = "error", f"gitleaks falló: {proc.stderr.strip()[-300:]}"
        return check
    for leak in json.loads(report.read_text() or "[]"):
        check.findings.append(Finding(leak.get("RuleID", "?"), leak.get("File", "?"),
                                      int(leak.get("StartLine", 0)), leak.get("Description", "secreto")))
    report.unlink()
    check.status = "blocked" if check.findings else "passed"
    return check


def check_sast(wt: Path, merge_base: str, head: str, use_registry: bool) -> Check:
    check = Check("sast", "semgrep")
    if not shutil.which("semgrep"):
        return _missing(check, "semgrep")
    # Las reglas de GitHub Actions las aplica el check `actions` (respeta --no-enforce-pins);
    # aqui solo van las de codigo, para no duplicar ni saltarse esa politica.
    configs = []
    for d in sorted(p for p in RULES_DIR.iterdir() if p.is_dir() and p.name != "github-actions"):
        configs += ["--config", str(d)]
    if use_registry:
        configs += ["--config", "p/python"]
    if (wt / "rules").is_dir():
        configs += ["--config", str(wt / "rules")]
    cmd = ["semgrep", "scan", *configs, "--metrics=off", "--severity", "ERROR", "--json",
           "--exclude", ".auditgate"]
    if merge_base != head:
        cmd += ["--baseline-commit", merge_base]
    proc = subprocess.run(cmd, cwd=wt, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        check.status, check.detail = "error", f"semgrep falló: {proc.stderr.strip()[-300:]}"
        return check
    fatal = [e for e in data.get("errors", []) if e.get("level") == "error"]
    for r in data.get("results", []):
        # Con --config <ruta> semgrep antepone la ruta al id; nos quedamos con auditgate.<grupo>.<regla>.
        m = re.search(r"(auditgate\.[\w-]+\.[\w-]+)$", r["check_id"])
        rule = m.group(1) if m else r["check_id"]
        check.findings.append(Finding(rule, r["path"], r["start"]["line"],
                                      r["extra"].get("message", "").strip()[:240]))
    if fatal and not check.findings:
        check.status = "error"
        check.detail = f"semgrep: {fatal[0].get('message', '')[:240]}"
        return check
    check.status = "blocked" if check.findings else "passed"
    if not use_registry:
        check.detail = "solo reglas de Auditgate (sin registro de Semgrep)"
    return check


def check_deps(wt: Path, merge_base: str, files: list[str]) -> Check:
    check = Check("deps", "pip-audit")
    if not files:
        check.status, check.detail = "skipped", "no hay requirements*.txt"
        return check
    if not shutil.which("pip-audit"):
        return _missing(check, "pip-audit")
    from auditgate.depgate import evaluate

    try:
        results = evaluate(merge_base, files, cwd=wt)
    except RuntimeError as exc:
        check.status, check.detail = "error", str(exc)[:300]
        return check
    debt = 0
    for res in results:
        debt += len(res["head"]) - len(res["new"])
        for name, ver, vid in res["new"]:
            check.findings.append(Finding(vid, res["file"], 0, f"{name}=={ver} vulnerable"))
    check.status = "blocked" if check.findings else "passed"
    if debt:
        check.detail = f"{debt} vulnerabilidad(es) previa(s): deuda, no bloquea"
    return check


def check_actions(wt: Path, enforce: bool) -> Check:
    check = Check("actions", "auditgate")
    for hit in unpinned_actions(wt):
        loc, ref = hit.split("  ", 1)
        path, line = loc.rsplit(":", 1)
        check.findings.append(Finding("auditgate.gha.action-not-pinned-to-sha", path, int(line),
                                      f"{ref} no está fijada por SHA", "error" if enforce else "warning"))
    if check.findings:
        check.status = "blocked" if enforce else "passed"
        if not enforce:
            check.detail = "solo reporte (--no-enforce-pins)"
    return check


# ── orquestacion ─────────────────────────────────────────────────────────────
def run_scan(repo: Path, base: str | None = None, checks: tuple[str, ...] = ALL_CHECKS,
             requirements: list[str] | None = None, use_registry: bool = True,
             enforce_pins: bool = True, strict: bool = False) -> dict:
    repo = Path(_git("rev-parse", "--show-toplevel", cwd=repo))
    base_ref = resolve_base(repo, base)
    head = _git("rev-parse", "HEAD", cwd=repo)
    merge_base = _git("merge-base", base_ref, "HEAD", cwd=repo)
    dirty = bool(_git("status", "--porcelain", cwd=repo))

    tmp = Path(tempfile.mkdtemp(prefix="auditgate-scan-"))
    wt = tmp / "wt"
    _git("worktree", "add", "--detach", str(wt), head, cwd=repo)
    try:
        reqs = requirements if requirements is not None else detect_project(wt)["requirements"].split()
        results: list[Check] = []
        for c in checks:
            if c == "secrets":
                results.append(check_secrets(wt, merge_base, head))
            elif c == "sast":
                results.append(check_sast(wt, merge_base, head, use_registry))
            elif c == "deps":
                results.append(check_deps(wt, merge_base, reqs))
            elif c == "actions":
                results.append(check_actions(wt, enforce_pins))
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=repo, capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)

    if strict:
        for r in results:
            if r.status == "skipped" and "no está instalado" in r.detail:
                r.status = "error"
    statuses = {r.status for r in results}
    gate = "error" if "error" in statuses else "blocked" if "blocked" in statuses else "passed"
    return {
        "auditgate_version": __version__,
        "gate": gate,
        "base": {"ref": base_ref, "merge_base": merge_base},
        "head": head,
        "uncommitted_changes": dirty,
        "checks": [asdict(r) for r in results],
        "summary": {
            "blocking_findings": sum(len(r.findings) for r in results if r.status == "blocked"),
            "skipped": [r.id for r in results if r.status == "skipped"],
        },
    }


def exit_code(report: dict) -> int:
    return {"passed": EXIT_PASSED, "blocked": EXIT_BLOCKED}.get(report["gate"], EXIT_ERROR)


ICONS = {"passed": "✔", "blocked": "✖", "skipped": "–", "error": "!"}


def render_text(report: dict) -> str:
    lines = [
        f"Auditgate scan — base {report['base']['ref']} ({report['base']['merge_base'][:7]})"
        f" → HEAD ({report['head'][:7]})"
    ]
    if report["uncommitted_changes"]:
        lines.append("  ⚠ tienes cambios sin commitear: no se evalúan (el PR solo lleva commits)")
    for c in report["checks"]:
        n = len(c["findings"])
        what = {"passed": f"{n} nuevos" if c["id"] != "actions" else "fijadas por SHA",
                "blocked": f"{n} nuevo(s) — BLOQUEA", "skipped": "omitido", "error": "error"}[c["status"]]
        lines.append(f"  {ICONS[c['status']]} {c['id']:<8} {c['tool']:<10} {what}"
                     + (f"  ({c['detail']})" if c["detail"] else ""))
        if c["status"] == "blocked":
            shown = c["findings"][:8]
            for f in shown:
                where = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                what = f"{f['message']} → {f['rule']}" if c["id"] == "deps" else f["rule"]
                lines.append(f"      {where}  {what}")
            if len(c["findings"]) > len(shown):
                lines.append(f"      … y {len(c['findings']) - len(shown)} más (usa --json para el detalle)")
    verdict = {
        "passed": "✅ Pasa: el PR no introduce problemas que el gate bloquee.",
        "blocked": f"🚫 Bloqueado: {report['summary']['blocking_findings']} hallazgo(s) nuevo(s).",
        "error": "⚠ Error: revisa la configuración o las herramientas.",
    }[report["gate"]]
    if report["summary"]["skipped"] and report["gate"] == "passed":
        verdict += f" (omitidos: {', '.join(report['summary']['skipped'])})"
    lines.append(verdict)
    return "\n".join(lines)
