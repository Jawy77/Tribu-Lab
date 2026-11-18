#!/usr/bin/env python3
"""
Gate de dependencias diff-aware (determinista).

- En un PR: audita cada requirements*.txt en BASE y en HEAD con pip-audit y
  FALLA solo si el PR introduce vulnerabilidades nuevas. La deuda previa se
  reporta pero no bloquea (se paga con Dependabot, no frenando a todo el equipo).
- En push: solo reporta.

Uso:
    python scripts/dep_gate.py --base <sha|""> req1.txt [req2.txt ...]
Salida: resumen markdown en $GITHUB_STEP_SUMMARY (si existe) y exit code.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def audit(req_text: str) -> set[tuple[str, str, str]]:
    """Devuelve {(paquete, version, vuln_id)} para el contenido de un requirements."""
    if not req_text.strip():
        return set()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(req_text)
        path = fh.name
    try:
        proc = subprocess.run(
            ["pip-audit", "-r", path, "-f", "json", "--progress-spinner", "off"],
            capture_output=True,
            text=True,
            check=False,
        )
        # pip-audit sale con 1 cuando encuentra vulns; eso no es un error de ejecucion.
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            raise RuntimeError(f"pip-audit fallo ({proc.returncode}): {proc.stderr[-500:]}")
        data = json.loads(proc.stdout)
    finally:
        os.unlink(path)
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    found = set()
    for dep in deps:
        for v in dep.get("vulns", []):
            found.add((dep["name"], dep.get("version", "?"), v["id"]))
    return found


def git_show(base: str, path: str) -> str:
    proc = subprocess.run(["git", "show", f"{base}:{path}"], capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else ""  # archivo nuevo en el PR


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="", help="SHA base del PR; vacio = modo reporte")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    lines = ["## 📦 Dependency gate (pip-audit, diff-aware)", ""]
    new_total: list[tuple[str, str, str, str]] = []
    for f in args.files:
        if not Path(f).exists():
            continue
        head = audit(Path(f).read_text())
        base = audit(git_show(args.base, f)) if args.base else set()
        base_ids = {vid for _, _, vid in base}
        new = {x for x in head if x[2] not in base_ids} if args.base else set()
        new_total += [(f, *x) for x in sorted(new)]
        lines.append(f"**`{f}`** — vulnerabilidades en HEAD: {len(head)} · nuevas en este PR: {len(new)}")
        for name, ver, vid in sorted(head):
            tag = "🆕 **NUEVA**" if (name, ver, vid) in new else "deuda previa"
            lines.append(f"- `{name}=={ver}` → `{vid}` ({tag})")
        lines.append("")

    if args.base and new_total:
        lines.append(f"> 🚫 **Bloqueado:** este PR introduce {len(new_total)} vulnerabilidad(es) nueva(s).")
    elif args.base:
        lines.append("> ✅ El PR no introduce vulnerabilidades nuevas en dependencias.")
    else:
        lines.append("> ℹ️ Modo reporte (push): la deuda se gestiona con Dependabot.")

    out = "\n".join(lines) + "\n"
    print(out)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(out)
    return 1 if (args.base and new_total) else 0


if __name__ == "__main__":
    sys.exit(main())
