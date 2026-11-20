"""Deteccion del proyecto y politica de actions fijadas (compartido por `init` y `scan`)."""
from __future__ import annotations

import glob
import re
import subprocess
from pathlib import Path

SKIP_DIRS = (".venv", "venv", "node_modules", ".auditgate", ".git")
UNPINNED = re.compile(r"uses:\s*[\"']?(?!\./|docker://)([\w.-]+/[\w./-]+)@(?![0-9a-f]{40}\b)([\w.-]+)")


def detect_project(root: Path) -> dict:
    skip = SKIP_DIRS
    reqs = sorted(
        p for p in glob.glob(str(root / "**/requirements*.txt"), recursive=True)
        if not any(part in skip for part in Path(p).relative_to(root).parts)
    )
    dockerfile = "Dockerfile" if (root / "Dockerfile").is_file() else ""
    tf_dirs = sorted({
        str(Path(p).parent.relative_to(root))
        for p in glob.glob(str(root / "**/*.tf"), recursive=True)
        if not any(part in skip for part in Path(p).relative_to(root).parts)
    })
    return {
        "requirements": " ".join(str(Path(r).relative_to(root)) for r in reqs),
        "dockerfile": dockerfile,
        "iac_dir": tf_dirs[0] if tf_dirs else "",
    }


def unpinned_actions(root: Path) -> list[str]:
    pattern = UNPINNED
    hits = []
    for wf in sorted((root / ".github/workflows").glob("*.y*ml")):
        for n, line in enumerate(wf.read_text(errors="ignore").splitlines(), 1):
            m = pattern.search(line)
            if m:
                hits.append(f"{wf.relative_to(root)}:{n}  {m.group(1)}@{m.group(2)}")
    return hits


# manifiesto → lockfiles que permiten saber que versiones se instalan de verdad
LOCKFILES = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock", "bun.lockb"),
    "Cargo.toml": ("Cargo.lock",),
    "Gemfile": ("Gemfile.lock",),
    "composer.json": ("composer.lock",),
}


def manifests_without_lockfile(root: Path) -> list[str]:
    """Manifiestos trackeados sin lockfile (ni en su carpeta ni en una superior: workspaces).

    Sin lockfile no se sabe que versiones se instalan, asi que el escaner de
    dependencias no puede revisarlas: hay que avisarlo en vez de dar verde.
    """
    proc = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True)
    if proc.returncode == 0:
        files = [Path(line) for line in proc.stdout.splitlines() if line]
    else:
        files = [p.relative_to(root) for p in root.rglob("*") if p.is_file()]
    tracked = {f.as_posix() for f in files}
    missing = []
    for f in files:
        locks = LOCKFILES.get(f.name)
        if not locks or any(part in SKIP_DIRS for part in f.parts):
            continue
        if "rules/" in f.as_posix():  # fixtures de reglas
            continue
        folders = [f.parent, *f.parent.parents]
        if not any((folder / lock).as_posix().lstrip("./") in tracked for folder in folders for lock in locks):
            missing.append(f.as_posix())
    return sorted(missing)
