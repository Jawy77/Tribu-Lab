#!/usr/bin/env python3
"""
Gate de dependencias diff-aware y multi-lenguaje (determinista).

Motor: osv-scanner (Google, Apache-2.0). Lee los manifiestos y lockfiles del
repo (npm, PyPI, Go, crates.io, Maven, RubyGems, Packagist, NuGet...) y resuelve
dependencias transitivas.

- En un PR: escanea la BASE y el HEAD y FALLA solo si el PR introduce
  vulnerabilidades nuevas. La deuda previa se reporta pero no bloquea (se paga
  con Dependabot, no frenando a todo el equipo).
- En push: solo reporta.

Lo usan el workflow de CI y `auditgate scan`: una sola implementacion.

Uso:
    python -m auditgate.depgate --base <sha|"">      # en la raiz del repo
Salida: resumen markdown (tambien en $GITHUB_STEP_SUMMARY) y exit code.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = "osv-scanner"


def _tool() -> str | None:
    from auditgate.tools import resolve

    return resolve(TOOL)


def osv_scan(directory: str | Path) -> list[dict]:
    """Vulnerabilidades del directorio, una por grupo de alias (CVE = GHSA = PYSEC cuentan como una).

    Cada item: {ecosystem, name, version, id, aliases, severity, source}
    """
    directory = Path(directory).resolve()
    proc = subprocess.run(
        [_tool() or TOOL, "scan", "source", "-r", str(directory), "--format", "json",
         "--allow-no-lockfiles", "--no-call-analysis=all"],
        capture_output=True, text=True, check=False,
    )
    # 0 = sin vulns · 1 = hay vulns. Cualquier otro codigo es un error de ejecucion.
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        raise RuntimeError(f"{TOOL} fallo ({proc.returncode}): {proc.stderr.strip()[-400:]}")
    data = json.loads(proc.stdout)
    found = []
    for result in data.get("results", []):
        source = result.get("source", {}).get("path", "")
        try:
            source = str(Path(source).resolve().relative_to(directory))
        except ValueError:
            pass
        for pkg in result.get("packages", []):
            meta = pkg.get("package", {})
            groups = pkg.get("groups") or [
                {"ids": [v["id"]], "aliases": v.get("aliases", [])} for v in pkg.get("vulnerabilities", [])
            ]
            for g in groups:
                ids = g.get("ids", []) + g.get("aliases", [])
                # Id estable para comparar base vs head: preferimos CVE, luego GHSA.
                vid = next((i for i in ids if i.startswith("CVE-")), None) \
                    or next((i for i in ids if i.startswith("GHSA-")), None) or (ids[0] if ids else "?")
                found.append({
                    "ecosystem": meta.get("ecosystem", "?"),
                    "name": meta.get("name", "?"),
                    "version": meta.get("version", "?"),
                    "id": vid,
                    "aliases": sorted(set(ids)),
                    "severity": g.get("max_severity") or "",
                    "source": source,
                })
    return found


def _key(v: dict) -> tuple[str, str, str]:
    # Sin version: subir de version sin arreglar la vuln no la convierte en "nueva".
    return (v["ecosystem"], v["name"], v["id"])


def evaluate(head_dir: str | Path, base_dir: str | Path | None = None) -> dict:
    """{"head": [...], "new": [...]} — `new` solo si se da `base_dir` (modo PR)."""
    head = osv_scan(head_dir)
    if base_dir is None:
        return {"head": head, "new": []}
    base_keys = {_key(v) for v in osv_scan(base_dir)}
    return {"head": head, "new": [v for v in head if _key(v) not in base_keys]}


def render(result: dict, pr_mode: bool) -> str:
    head, new = result["head"], result["new"]
    new_keys = {_key(v) for v in new}
    lines = ["## 📦 Dependency gate (osv-scanner, diff-aware)", ""]
    if not head:
        lines.append("Sin vulnerabilidades conocidas en las dependencias (o sin manifiestos).")
    else:
        ecos = sorted({v["ecosystem"] for v in head})
        lines.append(f"Ecosistemas: {', '.join(ecos)} · vulnerabilidades en HEAD: **{len(head)}** "
                     f"· nuevas en este PR: **{len(new)}**")
        lines += ["", "| Paquete | Vulnerabilidad | Sev. | Manifiesto | |", "|---|---|---|---|---|"]
        for v in sorted(head, key=lambda v: (_key(v) not in new_keys, v["source"], v["name"], v["id"]))[:60]:
            tag = "🆕 **NUEVA**" if _key(v) in new_keys else "deuda previa"
            lines.append(f"| `{v['name']}=={v['version']}` ({v['ecosystem']}) | `{v['id']}` | "
                         f"{v['severity'] or '—'} | `{v['source']}` | {tag} |")
        if len(head) > 60:
            lines.append(f"| … | y {len(head) - 60} más | | | |")
    lines.append("")
    if pr_mode and new:
        lines.append(f"> 🚫 **Bloqueado:** este PR introduce {len(new)} vulnerabilidad(es) nueva(s).")
    elif pr_mode:
        lines.append("> ✅ El PR no introduce vulnerabilidades nuevas en dependencias.")
    else:
        lines.append("> ℹ️ Modo reporte (push): la deuda se gestiona con Dependabot.")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", default="", help="SHA base del PR; vacio = modo reporte")
    ap.add_argument("--root", default=".", help="raiz del repo (default: directorio actual)")
    ap.add_argument("legacy_files", nargs="*", help=argparse.SUPPRESS)  # compat: antes recibia requirements
    args = ap.parse_args()

    if not _tool():
        print(f"✖ {TOOL} no está instalado. Corre `auditgate setup`.", file=sys.stderr)
        return 2
    root = Path(args.root).resolve()
    # HEAD y BASE se materializan en worktrees temporales: se escanea solo lo
    # commiteado (sin .auditgate/ ni archivos locales) y no se toca el checkout.
    tmp = Path(tempfile.mkdtemp(prefix="auditgate-deps-"))
    trees = {"head": "HEAD"} | ({"base": args.base} if args.base else {})
    try:
        for name, ref in trees.items():
            subprocess.run(["git", "worktree", "add", "--detach", str(tmp / name), ref],
                           cwd=root, check=True, capture_output=True)
        result = evaluate(tmp / "head", tmp / "base" if args.base else None)
    finally:
        for name in trees:
            subprocess.run(["git", "worktree", "remove", "--force", str(tmp / name)],
                           cwd=root, capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)

    out = render(result, pr_mode=bool(args.base))
    print(out)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(out)
    return 1 if (args.base and result["new"]) else 0


if __name__ == "__main__":
    sys.exit(main())
