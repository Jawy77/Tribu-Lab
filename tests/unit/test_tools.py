"""`auditgate setup`: nada se instala sin que el SHA-256 coincida con el fijado (sin red)."""
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from auditgate import tools

SCRIPT = b"#!/bin/sh\necho fake 1.0.0\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tarball(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    """Manifiesto de prueba servido desde disco; AUDITGATE_HOME aislado."""
    monkeypatch.setenv("AUDITGATE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(tools, "ALLOWED_URL_PREFIX", "file://")
    monkeypatch.setattr(tools, "platform_key", lambda: "test-plat")
    srv = tmp_path / "srv"
    srv.mkdir()

    def make(name: str, data: bytes, fmt: str, sha256: str | None = None, url: str | None = None) -> None:
        blob = srv / f"{name}.{fmt}"
        blob.write_bytes(data)
        manifest = {"tools": {name: {
            "purpose": "t", "version": "1.0.0", "license": "MIT", "binary": name,
            "assets": {"test-plat": {"url": url or blob.as_uri(), "sha256": sha256 or sha(data), "format": fmt}},
        }}}
        path = tmp_path / "tools.json"
        path.write_text(json.dumps(manifest))
        monkeypatch.setattr(tools, "MANIFEST_PATH", path)

    return make


def test_installs_binary_when_hash_matches_and_is_idempotent(env):
    env("fake", SCRIPT, "binary")
    path, downloaded = tools.install("fake", progress=False)
    assert downloaded and path.read_bytes() == SCRIPT and path.stat().st_mode & 0o111
    assert (tools.bin_dir() / "fake").resolve() == path.resolve()
    assert tools.resolve("fake") == str(path)
    assert tools.smoke_test(path) == "fake 1.0.0"
    assert tools.install("fake", progress=False) == (path, False)  # no vuelve a descargar


def test_hash_mismatch_installs_nothing(env):
    env("fake", SCRIPT, "binary", sha256="0" * 64)
    with pytest.raises(tools.ToolError, match="SHA-256 no coincide"):
        tools.install("fake", progress=False)
    assert not tools.installed_path("fake", tools.load_manifest()["fake"]).exists()
    assert not (tools.bin_dir() / "fake").exists()
    assert tools.resolve("fake") is None


def test_tar_extracts_only_the_expected_binary(env, tmp_path):
    data = tarball({"../../evil": b"x", "LICENSE": b"mit", "nested/fake": SCRIPT})
    env("fake", data, "tar.gz")
    path, _ = tools.install("fake", progress=False)
    assert path.read_bytes() == SCRIPT
    assert sorted(p.name for p in path.parent.iterdir()) == ["fake"]  # nada mas se escribio
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()


def test_tar_without_the_binary_fails(env):
    env("fake", tarball({"README": b"x"}), "tar.gz")
    with pytest.raises(tools.ToolError, match="no contiene el binario"):
        tools.install("fake", progress=False)


def test_rejects_urls_outside_the_allowlist(env, monkeypatch):
    env("fake", SCRIPT, "binary", url="https://evil.example.com/fake")
    monkeypatch.setattr(tools, "ALLOWED_URL_PREFIX", "https://github.com/")
    with pytest.raises(tools.ToolError, match="URL no permitida"):
        tools.install("fake", progress=False)


def test_unknown_tool_and_real_manifest_shape():
    with pytest.raises(tools.ToolError):
        tools.install("no-existe", progress=False)
    manifest = json.loads((Path(tools.__file__).parent / "tools.json").read_text())["tools"]
    assert set(manifest) == {"opengrep", "gitleaks", "osv-scanner"}
    for name, spec in manifest.items():
        assert set(spec["assets"]) == {"darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64"}, name
        for asset in spec["assets"].values():
            assert asset["url"].startswith("https://github.com/") and spec["version"] in asset["url"]
            assert len(asset["sha256"]) == 64 and asset["format"] in ("binary", "tar.gz")


def test_managed_tool_wins_over_path(env, monkeypatch):
    env("fake", SCRIPT, "binary")
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/local/bin/fake")
    assert tools.resolve("fake") == "/usr/local/bin/fake"  # aun no instalado: usa el PATH
    path, _ = tools.install("fake", progress=False)
    assert tools.resolve("fake") == str(path)  # instalado y verificado: gana
