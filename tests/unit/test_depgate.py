"""Gate de dependencias (osv-scanner): alias agrupados y solo lo nuevo bloquea (sin red)."""
import json
import subprocess

import pytest

from auditgate import depgate


def osv_output(*packages):
    return json.dumps({"results": [{"source": {"path": "/x/web/package-lock.json"}, "packages": list(packages)}]})


def pkg(name, version, groups, eco="npm"):
    return {"package": {"name": name, "version": version, "ecosystem": eco},
            "groups": [{"ids": ids, "aliases": aliases, "max_severity": sev} for ids, aliases, sev in groups]}


LODASH_OLD = pkg("lodash", "4.17.15", [(["GHSA-p6mc-m468-83gw"], ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"], "7.4")])
LODASH_BUMPED_STILL_VULN = pkg("lodash", "4.17.16", [(["GHSA-p6mc-m468-83gw"], ["CVE-2020-8203"], "7.4")])
REQUESTS = pkg("requests", "2.19.0", [(["PYSEC-2018-28", "GHSA-x84v-xcm2-53pg"], ["CVE-2018-18074"], "7.5")], eco="PyPI")


def fake_osv(monkeypatch, by_dir):
    def run(cmd, **kw):
        target = cmd[4]
        out = next(v for k, v in by_dir.items() if k in target)
        return subprocess.CompletedProcess(cmd, 1 if '"packages": [{' in out else 0, stdout=out, stderr="")

    monkeypatch.setattr(depgate.subprocess, "run", run)


def test_aliases_collapse_to_one_finding_preferring_cve(monkeypatch, tmp_path):
    fake_osv(monkeypatch, {str(tmp_path): osv_output(REQUESTS)})
    found = depgate.osv_scan(tmp_path)
    assert len(found) == 1  # PYSEC + GHSA + CVE = una sola vulnerabilidad
    assert found[0]["id"] == "CVE-2018-18074" and found[0]["ecosystem"] == "PyPI"
    assert found[0]["severity"] == "7.5"


def test_only_new_vulns_block(monkeypatch, tmp_path):
    head, base = tmp_path / "head", tmp_path / "base"
    head.mkdir(); base.mkdir()
    fake_osv(monkeypatch, {str(head): osv_output(LODASH_OLD, REQUESTS), str(base): osv_output(LODASH_OLD)})
    result = depgate.evaluate(head, base)
    assert len(result["head"]) == 2
    assert [v["name"] for v in result["new"]] == ["requests"]  # lodash es deuda previa


def test_version_bump_that_keeps_the_vuln_is_not_new(monkeypatch, tmp_path):
    head, base = tmp_path / "head", tmp_path / "base"
    head.mkdir(); base.mkdir()
    fake_osv(monkeypatch, {str(head): osv_output(LODASH_BUMPED_STILL_VULN), str(base): osv_output(LODASH_OLD)})
    assert depgate.evaluate(head, base)["new"] == []


def test_report_mode_never_blocks_and_render_marks_new(monkeypatch, tmp_path):
    fake_osv(monkeypatch, {str(tmp_path): osv_output(LODASH_OLD)})
    result = depgate.evaluate(tmp_path)
    assert result["new"] == []
    assert "Modo reporte" in depgate.render(result, pr_mode=False)
    text = depgate.render({"head": result["head"], "new": result["head"]}, pr_mode=True)
    assert "NUEVA" in text and "Bloqueado" in text


def test_tool_crash_is_an_error_not_a_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(depgate.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 127, stdout="", stderr="boom"))
    with pytest.raises(RuntimeError):
        depgate.osv_scan(tmp_path)
