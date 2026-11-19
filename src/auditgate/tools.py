"""
Motores que orquesta Auditgate: instalacion verificada y resolucion de rutas.

`auditgate setup` descarga cada motor de su release oficial, verifica su SHA-256
contra el fijado en tools.json y lo deja en ~/.auditgate/. Nunca ejecuta nada
que no coincida con el hash. El workflow de CI usa este mismo modulo y este
mismo manifiesto: tu maquina y GitHub corren exactamente las mismas versiones.

    ~/.auditgate/tools/<motor>/<version>/<binario>
    ~/.auditgate/bin/<binario>  ->  enlace al anterior

Uso en CI:
    python -m auditgate.tools install            # todos
    python -m auditgate.tools install gitleaks   # uno
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parent / "tools.json"
ALLOWED_URL_PREFIX = "https://github.com/"  # solo releases oficiales en GitHub


class ToolError(RuntimeError):
    pass


def home() -> Path:
    return Path(os.environ.get("AUDITGATE_HOME") or Path.home() / ".auditgate")


def bin_dir() -> Path:
    return home() / "bin"


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())["tools"]


def platform_key() -> str:
    system = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        platform.machine().lower()
    )
    if not system or not machine:
        raise ToolError(
            f"Plataforma no soportada: {sys.platform}/{platform.machine()}. "
            "Soportadas: macOS y Linux (arm64, x86_64). En Windows usa WSL."
        )
    return f"{system}-{machine}"


def installed_path(name: str, spec: dict) -> Path:
    return home() / "tools" / name / spec["version"] / spec["binary"]


def resolve(name: str) -> str | None:
    """Ruta del motor: primero el instalado por `auditgate setup`, despues el PATH."""
    spec = load_manifest().get(name)
    if spec:
        managed = installed_path(name, spec)
        if managed.is_file() and os.access(managed, os.X_OK):
            return str(managed)
    return shutil.which(name)


def status() -> list[dict]:
    rows = []
    for name, spec in load_manifest().items():
        managed = installed_path(name, spec)
        path = resolve(name)
        rows.append({
            "name": name, "purpose": spec["purpose"], "version": spec["version"],
            "managed": managed.is_file(), "path": path,
            "source": "auditgate setup" if managed.is_file() else ("PATH (versión no verificada)" if path else None),
        })
    return rows


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, progress: bool) -> None:
    if not url.startswith(ALLOWED_URL_PREFIX):
        raise ToolError(f"URL no permitida en el manifiesto: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "auditgate-setup"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as out:  # noqa: S310
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while chunk := resp.read(1 << 20):
            out.write(chunk)
            done += len(chunk)
            if progress and total and sys.stderr.isatty():
                print(f"\r      {done * 100 // total:3d}%  {done >> 20}/{total >> 20} MB", end="", file=sys.stderr)
    if progress and sys.stderr.isatty():
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)


def _extract_binary(archive: Path, binary: str, dest: Path) -> None:
    """Extrae SOLO el binario esperado del tar.gz (ignora cualquier otra ruta del archivo)."""
    with tarfile.open(archive, "r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.isfile() and Path(m.name).name == binary), None)
        if member is None:
            raise ToolError(f"El archivo no contiene el binario '{binary}'.")
        src = tar.extractfile(member)
        with dest.open("wb") as out:
            shutil.copyfileobj(src, out)


def install(name: str, force: bool = False, progress: bool = True) -> tuple[Path, bool]:
    """Instala un motor verificando su hash. Devuelve (ruta, se_descargo)."""
    manifest = load_manifest()
    if name not in manifest:
        raise ToolError(f"Motor desconocido: {name}. Disponibles: {', '.join(manifest)}")
    spec = manifest[name]
    key = platform_key()
    asset = spec["assets"].get(key)
    if not asset:
        raise ToolError(f"{name} {spec['version']} no tiene binario para {key}.")
    target = installed_path(name, spec)
    if target.is_file() and not force:
        _link(name, spec, target)
        return target, False

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="auditgate-dl-", dir=target.parent) as tmp:
        blob = Path(tmp) / "download"
        _download(asset["url"], blob, progress)
        actual = _sha256(blob)
        # Lo descargado NO se ejecuta ni se extrae si el hash no coincide con el fijado.
        if not hmac.compare_digest(actual, asset["sha256"]):
            raise ToolError(
                f"{name} {spec['version']}: el SHA-256 no coincide con el fijado.\n"
                f"  esperado: {asset['sha256']}\n  obtenido: {actual}\n"
                "No se instaló nada. Puede ser un release reemplazado o una descarga manipulada."
            )
        staged = Path(tmp) / spec["binary"]
        if asset["format"] == "tar.gz":
            _extract_binary(blob, spec["binary"], staged)
        elif asset["format"] == "binary":
            blob.rename(staged)
        else:
            raise ToolError(f"Formato no soportado en el manifiesto: {asset['format']}")
        staged.chmod(0o755)
        os.replace(staged, target)  # atomico: nunca queda un binario a medias
    _link(name, spec, target)
    return target, True


def _link(name: str, spec: dict, target: Path) -> None:
    bin_dir().mkdir(parents=True, exist_ok=True)
    link = bin_dir() / spec["binary"]
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)


def smoke_test(path: Path) -> str:
    """Corre `--version`/`version` para confirmar que el binario ejecuta en esta maquina."""
    for args in (["--version"], ["version"]):
        proc = subprocess.run([str(path), *args], capture_output=True, text=True, timeout=60)
        out = (proc.stdout or proc.stderr).strip().splitlines()
        if proc.returncode == 0 and out:
            return out[0][:80]
    return "(no respondió a --version)"


def main() -> int:
    ap = argparse.ArgumentParser(description="Instala los motores de Auditgate con hash verificado")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("install")
    p.add_argument("names", nargs="*", help="motores (default: todos)")
    p.add_argument("--force", action="store_true")
    args = ap.parse_args()
    names = args.names or list(load_manifest())
    try:
        for name in names:
            path, downloaded = install(name, force=args.force, progress=False)
            print(f"{'instalado ' if downloaded else 'ya estaba '} {name} → {path}")
    except ToolError as exc:
        print(f"✖ {exc}", file=sys.stderr)
        return 2
    # En GitHub Actions, deja los motores en el PATH de los pasos siguientes.
    gh_path = os.environ.get("GITHUB_PATH")
    if gh_path:
        with open(gh_path, "a") as fh:
            fh.write(f"{bin_dir()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
