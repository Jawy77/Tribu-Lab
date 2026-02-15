#!/usr/bin/env python3
"""
Helper para actualizar status.json en tiempo real durante el demo.

Uso:
    python3 update_dashboard_status.py <status.json> reset
    python3 update_dashboard_status.py <status.json> stage <name> <status> <findings>
    python3 update_dashboard_status.py <status.json> log <level> <event> <message>
    python3 update_dashboard_status.py <status.json> pipeline <complete|failed>
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

INITIAL_STATUS = {
    "pipeline": {
        "status": "running",
        "last_run": "",
        "commit": "429e1bf",
        "branch": "main",
        "duration_seconds": 0,
        "trigger": "demo (live)",
        "stages": {
            "secret-scan": {"status": "pending", "duration_seconds": 0, "findings": 0},
            "bandit-sast": {"status": "pending", "duration_seconds": 0, "findings": 0},
            "semgrep-sast": {"status": "pending", "duration_seconds": 0, "findings": 0},
            "safety-deps": {"status": "pending", "duration_seconds": 0, "findings": 0},
            "container-security": {"status": "skipped", "duration_seconds": 0, "findings": 0},
            "iac-security": {"status": "skipped", "duration_seconds": 0, "findings": 0},
        },
    },
    "vulnerabilities": [],
    "scan_summary": {},
    "architecture": {
        "nodes": [
            {"id": "vpn-hub", "label": "VPN Hub", "type": "server", "ip": "10.10.0.1", "status": "online", "services": ["WireGuard", "Nginx mTLS", "Monitoring"]},
            {"id": "parrot", "label": "Parrot OS", "type": "workstation", "ip": "10.10.0.2", "status": "online", "services": ["Bandit", "Semgrep", "Claude Code"]},
            {"id": "agent", "label": "Agent Node", "type": "agent", "ip": "10.10.0.3", "status": "online", "services": ["Docker", "Pipeline Runner", "Trivy"]},
        ],
        "connections": [
            {"from": "parrot", "to": "vpn-hub", "protocol": "WireGuard", "port": 51820},
            {"from": "agent", "to": "vpn-hub", "protocol": "WireGuard", "port": 51820},
            {"from": "parrot", "to": "agent", "protocol": "mTLS", "port": 443},
        ],
    },
    "activity_log": [
        {
            "timestamp": "",
            "event": "pipeline_start",
            "message": "Demo en vivo iniciado — Pipeline DevSecOps arrancando",
            "level": "info",
        }
    ],
}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_status(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return INITIAL_STATUS.copy()


def save_status(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_reset(path):
    data = json.loads(json.dumps(INITIAL_STATUS))
    data["pipeline"]["last_run"] = now_iso()
    data["activity_log"][0]["timestamp"] = now_iso()
    save_status(path, data)


def cmd_stage(path, name, status, findings):
    data = load_status(path)
    if name in data["pipeline"]["stages"]:
        data["pipeline"]["stages"][name]["status"] = status
        data["pipeline"]["stages"][name]["findings"] = int(findings)
    save_status(path, data)


def cmd_log(path, level, event, message):
    data = load_status(path)
    entry = {
        "timestamp": now_iso(),
        "event": event,
        "message": message,
        "level": level,
    }
    data["activity_log"].insert(0, entry)
    save_status(path, data)


def cmd_pipeline(path, status):
    data = load_status(path)
    if status == "complete":
        failed = any(
            s["status"] == "failed"
            for s in data["pipeline"]["stages"].values()
        )
        data["pipeline"]["status"] = "warning" if failed else "passed"
    else:
        data["pipeline"]["status"] = "failed"
    data["pipeline"]["last_run"] = now_iso()

    entry = {
        "timestamp": now_iso(),
        "event": "pipeline_complete",
        "message": f"Pipeline finalizado — Status: {data['pipeline']['status'].upper()}",
        "level": "success" if not failed else "warning",
    }
    data["activity_log"].insert(0, entry)
    save_status(path, data)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: update_dashboard_status.py <status.json> <command> [args...]")
        sys.exit(1)

    path = sys.argv[1]
    cmd = sys.argv[2]

    if cmd == "reset":
        cmd_reset(path)
    elif cmd == "stage" and len(sys.argv) >= 6:
        cmd_stage(path, sys.argv[3], sys.argv[4], sys.argv[5])
    elif cmd == "log" and len(sys.argv) >= 6:
        cmd_log(path, sys.argv[3], sys.argv[4], " ".join(sys.argv[5:]))
    elif cmd == "pipeline" and len(sys.argv) >= 4:
        cmd_pipeline(path, sys.argv[3])
    else:
        print(f"Comando desconocido: {cmd}")
        sys.exit(1)
