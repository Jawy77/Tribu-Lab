"""
Lenguajes del repo y cobertura de SAST: el gate nunca debe dar un verde enganoso.

Detecta los lenguajes por extension (archivos trackeados por git), arma la lista
de reglas a aplicar y dice que lenguajes quedan SIN cobertura:

  - reglas propias de Auditgate (MIT, con tests)            → siempre
  - reglas propias del repo (`rules/`)                       → si existen
  - set del registro de Semgrep por lenguaje (p/python, ...) → salvo --no-registry
    (cada usuario las descarga para su propio uso; Auditgate no las redistribuye)

Uso en CI:
    python -m auditgate.languages --semgrep-configs     # imprime los --config
    python -m auditgate.languages --summary              # tabla markdown de cobertura
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from auditgate.project import SKIP_DIRS

RULES_DIR = Path(__file__).resolve().parent / "rules"

# extension → lenguaje
EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c",
    ".scala": "scala",
    ".swift": "swift",
    # Lenguajes que detectamos para AVISAR que no tienen cobertura de SAST:
    ".dart": "dart", ".ex": "elixir", ".exs": "elixir", ".lua": "lua", ".pl": "perl",
    ".m": "objective-c", ".clj": "clojure", ".hs": "haskell", ".erl": "erlang",
    ".sol": "solidity", ".zig": "zig", ".groovy": "groovy",
}

# lenguaje → set del registro de Semgrep (verificados: responden 200 en semgrep.dev/c/p/<nombre>)
REGISTRY_PACKS = {
    "python": "p/python", "javascript": "p/javascript", "typescript": "p/typescript",
    "go": "p/golang", "java": "p/java", "kotlin": "p/kotlin", "ruby": "p/ruby",
    "php": "p/php", "csharp": "p/csharp", "rust": "p/rust", "c": "p/c",
    "scala": "p/scala", "swift": "p/swift",
}

# nombres que usa semgrep en `languages:` → nuestros nombres
RULE_LANG_ALIASES = {
    "py": "python", "python3": "python", "js": "javascript", "ts": "typescript",
    "golang": "go", "kt": "kotlin", "rb": "ruby", "c#": "csharp", "cs": "csharp",
    "cpp": "c", "c++": "c", "rs": "rust",
}
_LANG_LINE = re.compile(r"^\s*languages:\s*\[([^\]]*)\]", re.MULTILINE)


def detect(root: Path) -> dict[str, int]:
    """{lenguaje: numero de archivos} para el codigo trackeado por git en `root`."""
    proc = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True)
    if proc.returncode == 0:
        files = [Path(line) for line in proc.stdout.splitlines() if line]
    else:  # no es un repo git: recorrido simple
        files = [p.relative_to(root) for p in root.rglob("*") if p.is_file()]
    counts: dict[str, int] = {}
    for f in files:
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        # Los fixtures de reglas son vulnerables a proposito: no son codigo del producto.
        posix = f.as_posix()
        if posix.startswith("rules/") or "auditgate/rules/" in posix:
            continue
        lang = EXTENSIONS.get(f.suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def rule_languages(*dirs: Path) -> set[str]:
    """Lenguajes que cubren las reglas (yml) de los directorios dados."""
    langs: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for yml in list(d.rglob("*.yml")) + list(d.rglob("*.yaml")):
            if ".test." in yml.name:
                continue
            for group in _LANG_LINE.findall(yml.read_text(errors="ignore")):
                for raw in group.split(","):
                    name = raw.strip().strip("\"'").lower()
                    if name and name not in ("regex", "generic", "yaml", "json", "dockerfile", "terraform", "hcl"):
                        langs.add(RULE_LANG_ALIASES.get(name, name))
    return langs


def platform_rule_dirs() -> list[Path]:
    """Reglas de codigo de Auditgate. Las de GitHub Actions las aplica el control `actions`."""
    return sorted(p for p in RULES_DIR.iterdir() if p.is_dir() and p.name != "github-actions")


def sast_plan(root: Path, use_registry: bool = True) -> dict:
    """Que lenguajes hay, con que reglas se escanean y cuales quedan sin cobertura."""
    detected = detect(root)
    repo_rules = root / "rules"
    rule_dirs = platform_rule_dirs() + ([repo_rules] if repo_rules.is_dir() else [])
    own = rule_languages(*rule_dirs)

    configs = [str(d) for d in rule_dirs]
    coverage: dict[str, list[str]] = {}
    for lang in detected:
        sources = []
        if lang in own:
            sources.append("reglas propias")
        pack = REGISTRY_PACKS.get(lang)
        if use_registry and pack:
            sources.append(pack)
            configs.append(pack)
        coverage[lang] = sources
    return {
        "languages": detected,
        "configs": configs,
        "coverage": coverage,
        "uncovered": [lang for lang, src in coverage.items() if not src],
    }


def render_summary(plan: dict) -> str:
    if not plan["languages"]:
        return "## 🗺️ Cobertura de SAST\n\nNo se detectó código en lenguajes conocidos.\n"
    lines = ["## 🗺️ Cobertura de SAST", "", "| Lenguaje | Archivos | Reglas |", "|---|---|---|"]
    for lang, n in plan["languages"].items():
        src = plan["coverage"][lang]
        lines.append(f"| {lang} | {n} | {', '.join(src) if src else '⚠️ **sin cobertura**'} |")
    if plan["uncovered"]:
        lines += ["", f"> ⚠️ Sin reglas de SAST para: **{', '.join(plan['uncovered'])}**. "
                      "El gate NO revisó ese código. Agrega reglas en `rules/` o revísalo manualmente."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Lenguajes detectados y cobertura de SAST")
    ap.add_argument("--root", default=".")
    ap.add_argument("--no-registry", action="store_true")
    ap.add_argument("--semgrep-configs", action="store_true", help="imprime los argumentos --config")
    ap.add_argument("--summary", action="store_true", help="imprime la tabla markdown de cobertura")
    ap.add_argument("--github", action="store_true", help="emite ::warning:: si hay lenguajes sin cobertura")
    args = ap.parse_args()
    plan = sast_plan(Path(args.root), use_registry=not args.no_registry)
    if args.semgrep_configs:
        print(" ".join(f"--config {c}" for c in plan["configs"]))
    if args.summary:
        print(render_summary(plan))
    if args.github and plan["uncovered"]:
        print(f"::warning title=Auditgate: SAST sin cobertura::Lenguajes sin reglas: {', '.join(plan['uncovered'])}. "
              "El gate no revisó ese código.", file=sys.stderr if args.semgrep_configs else sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
