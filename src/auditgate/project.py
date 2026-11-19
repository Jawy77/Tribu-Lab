"""Deteccion del proyecto y politica de actions fijadas (compartido por `init` y `scan`)."""
from __future__ import annotations

import glob
import re
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
