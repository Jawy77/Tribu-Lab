# =============================================================================
# APLICACION SEGURA — Todas las vulnerabilidades corregidas
# Bunker DevSecOps Workshop
# =============================================================================
# Correcciones aplicadas:
#   1. Hardcoded secrets    -> Variables de entorno
#   2. SQL Injection        -> Parameterized queries
#   3. Command Injection    -> Sin shell=True + validacion de input
#   4. Insecure deserialize -> JSON en lugar de pickle
#   5. Path Traversal       -> Sanitizacion de rutas + directorio base
#   6. SSRF                 -> Allowlist de dominios + validacion de esquema
#   7. Debug mode           -> Controlado por variable de entorno
# =============================================================================

import json
import logging
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request

app = Flask(__name__)

# ── FIX 1: Secrets desde variables de entorno ────────────────
# Severidad original: CRITICAL (CWE-798)
# Antes: SECRET_KEY = "super_secret_key_12345"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
API_KEY = os.environ.get("API_KEY")

# Logging en lugar de exponer errores al usuario
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Directorio base para servir archivos (FIX 5)
BASE_DATA_DIR = Path("/app/data").resolve()

# Dominios permitidos para fetch (FIX 6)
ALLOWED_FETCH_DOMAINS = {"api.github.com", "httpbin.org"}
ALLOWED_SCHEMES = {"http", "https"}


# ── FIX 2: SQL Injection -> Parameterized queries ────────────
# Severidad original: Medium (CWE-89, B608)
# Antes: f"SELECT * FROM users WHERE username = '{username}'"
@app.route("/user/<username>")
def get_user(username):
    """Seguro: parameterized query previene SQL injection."""
    conn = sqlite3.connect("users.db")
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        )
        result = cursor.fetchone()
        return jsonify({"user": result})
    except sqlite3.Error:
        logger.exception("Database error in get_user")
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()


# ── FIX 3: Command Injection -> Sin shell, input validado ────
# Severidad original: HIGH (CWE-78, B602)
# Antes: subprocess.run(f"ping -c 1 {host}", shell=True, ...)
@app.route("/ping")
def ping_host():
    """Seguro: sin shell=True, IP validada con regex."""
    host = request.args.get("host", "127.0.0.1")

    # Validar formato de IP (solo IPv4)
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return jsonify({"error": "Invalid IP address format"}), 400

    # Validar rango de octetos (0-255)
    octets = host.split(".")
    if any(int(o) > 255 for o in octets):
        return jsonify({"error": "Invalid IP address range"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "3", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify({"output": result.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 504


# ── FIX 4: Pickle -> JSON seguro ─────────────────────────────
# Severidad original: Medium (CWE-502, B301)
# Antes: pickle.loads(data) — permite ejecucion de codigo arbitrario
@app.route("/load", methods=["POST"])
def load_data():
    """Seguro: JSON en lugar de pickle para deserializacion."""
    try:
        data = request.get_json(force=False)
        if data is None:
            return jsonify({"error": "Invalid JSON payload"}), 400
        return jsonify({"loaded": data})
    except Exception:
        logger.exception("Error parsing JSON in load_data")
        return jsonify({"error": "Invalid data format"}), 400


# ── FIX 5: Path Traversal -> Ruta sanitizada ─────────────────
# Severidad original: HIGH (CWE-22)
# Antes: open(f"/app/data/{filename}") sin validacion
@app.route("/file")
def read_file():
    """Seguro: resuelve la ruta y verifica que este dentro del directorio base."""
    filename = request.args.get("name", "readme.txt")

    # Rechazar patrones de traversal obvios
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Invalid filename"}), 400

    # Resolver la ruta completa y verificar que no escape del directorio base
    requested_path = (BASE_DATA_DIR / filename).resolve()
    if not str(requested_path).startswith(str(BASE_DATA_DIR)):
        return jsonify({"error": "Access denied"}), 403

    try:
        with open(requested_path) as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except OSError:
        logger.exception("Error reading file %s", filename)
        return jsonify({"error": "Cannot read file"}), 500


# ── FIX 6: SSRF -> Allowlist de dominios ─────────────────────
# Severidad original: Medium (CWE-918, B310)
# Antes: urllib.request.urlopen(url) sin ninguna validacion
@app.route("/fetch")
def fetch_url():
    """Seguro: solo dominios en allowlist, solo HTTP/HTTPS."""
    import urllib.request

    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "URL parameter required"}), 400

    # Parsear y validar la URL
    parsed = urlparse(url)

    # Solo permitir esquemas HTTP/HTTPS (bloquea file://, gopher://, etc.)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return jsonify({"error": f"Scheme not allowed. Use: {ALLOWED_SCHEMES}"}), 400

    # Solo permitir dominios en la allowlist
    if parsed.hostname not in ALLOWED_FETCH_DOMAINS:
        return jsonify({"error": f"Domain not allowed. Allowed: {ALLOWED_FETCH_DOMAINS}"}), 403

    try:
        response = urllib.request.urlopen(url, timeout=5)  # nosec B310 — validated via allowlist
        content = response.read().decode("utf-8", errors="replace")
        return jsonify({"content": content})
    except Exception:
        logger.exception("Error fetching URL %s", parsed.hostname)
        return jsonify({"error": "Failed to fetch URL"}), 502


# ── FIX 7: Debug mode controlado por entorno ─────────────────
# Severidad original: HIGH (CWE-94, B201) + Medium (CWE-605, B104)
# Antes: app.run(host="0.0.0.0", port=5000, debug=True)
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=debug_mode)
