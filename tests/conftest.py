"""
Fixtures y markers para tests de seguridad alineados a OWASP Top 10 2021.
Bunker DevSecOps Workshop — Tribu | Hacklab Bogota | Ethereum Bogota
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directorios excluidos de scans de produccion
# vulnerable_app/ es intencional, tests/ se autoreferencian,
# devsecops-bunker-workshop/ es copia de respaldo empaquetada
EXCLUDED_DIRS = {
    "vulnerable_app",
    "tests",
    "devsecops-bunker-workshop",
    "devsecops-pipeline",
    ".venv",
    "venv",
    "__pycache__",
}


def pytest_configure(config):
    """Registrar markers personalizados para evitar warnings de pytest."""
    config.addinivalue_line("markers", "security: Tests de seguridad general")
    config.addinivalue_line("markers", "owasp_a02: A02:2021 Cryptographic Failures")
    config.addinivalue_line("markers", "owasp_a03: A03:2021 Injection")
    config.addinivalue_line("markers", "owasp_a05: A05:2021 Security Misconfiguration")
    config.addinivalue_line("markers", "owasp_a06: A06:2021 Vulnerable and Outdated Components")
    config.addinivalue_line("markers", "owasp_a07: A07:2021 Identification and Authentication Failures")


def _is_excluded(path: Path) -> bool:
    """Retorna True si el archivo esta dentro de un directorio excluido."""
    parts = path.relative_to(REPO_ROOT).parts
    return any(p in EXCLUDED_DIRS for p in parts)


def code_lines(content: str):
    """Yield (lineno, line) solo para lineas de codigo activo.

    Salta comentarios (#) y docstrings (triple-quoted strings).
    Util para buscar patrones peligrosos sin falsos positivos en documentacion.
    """
    in_docstring = False
    docstring_delim = None
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()

        if in_docstring:
            if docstring_delim in stripped:
                in_docstring = False
            continue

        if stripped.startswith("#"):
            continue

        for delim in ('"""', "'''"):
            if delim in stripped:
                count = stripped.count(delim)
                if count == 1:
                    in_docstring = True
                    docstring_delim = delim
                    break
                # count >= 2: single-line docstring — skip it
                break
        else:
            yield i, line
            continue
        # If we broke out of the for loop (found a docstring), skip this line
        continue


@pytest.fixture
def repo_root():
    """Directorio raiz del repositorio."""
    return REPO_ROOT


@pytest.fixture
def python_source_files():
    """Archivos .py de produccion (fuera de vulnerable_app/, tests/, backups)."""
    return [f for f in REPO_ROOT.rglob("*.py") if not _is_excluded(f)]


@pytest.fixture
def dockerfiles():
    """Dockerfiles del proyecto (excluyendo copias de respaldo)."""
    return [f for f in REPO_ROOT.rglob("Dockerfile*") if not _is_excluded(f)]


@pytest.fixture
def terraform_files():
    """Archivos .tf del proyecto (excluyendo copias de respaldo)."""
    return [f for f in REPO_ROOT.rglob("*.tf") if not _is_excluded(f)]
