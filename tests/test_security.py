"""
Security Tests — OWASP Top 10 2021 Alignment
Bunker DevSecOps Workshop — Tribu | Hacklab Bogota | Ethereum Bogota

22 tests organizados por categoria OWASP.
Cada test tiene docstring explicando el OWASP ID y por que importa.

Ejecutar:
    pytest tests/ -v
    pytest tests/ -v -m security
    pytest tests/ -v -m owasp_a03
"""

import re
import subprocess
from pathlib import Path

import pytest

from conftest import code_lines

REPO_ROOT = Path(__file__).resolve().parent.parent


# =================================================================
# Grupo 1 — Secrets (OWASP A07:2021)
# Identification and Authentication Failures
# =================================================================


@pytest.mark.security
@pytest.mark.owasp_a07
class TestSecrets:
    """OWASP A07:2021 — No debe haber secrets hardcodeados fuera de vulnerable_app/."""

    def test_no_hardcoded_passwords_in_config(self, python_source_files):
        """A07:2021 — Passwords hardcodeados en codigo permiten acceso no autorizado
        si el repositorio se filtra o se hace publico. Segun GitGuardian 2024,
        el 12.8% de commits en GitHub contienen al menos un secret. Buscamos
        patrones PASSWORD = '...' en archivos Python de produccion.
        """
        pattern = re.compile(
            r"""(?:password|passwd|pwd)\s*=\s*["'][^"']+["']""",
            re.IGNORECASE,
        )
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if pattern.search(line):
                    violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, (
            f"Passwords hardcodeados encontrados en: {violations}"
        )

    def test_no_api_keys_in_source(self, python_source_files):
        """A07:2021 — API keys en codigo fuente son el vector #1 de filtraciones.
        Un key hardcodeado (sk-xxx, AKIA, ghp_) puede ser explotado en segundos
        por bots que escanean repos publicos. Verificamos que no hay keys reales
        en archivos Python de produccion.
        """
        patterns = [
            re.compile(r"""["']sk-[a-zA-Z0-9]{10,}["']"""),
            re.compile(r"""api_key\s*=\s*["'][a-zA-Z0-9]{10,}["']""", re.IGNORECASE),
            re.compile(r"""token\s*=\s*["'][a-zA-Z0-9]{20,}["']""", re.IGNORECASE),
        ]
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                for p in patterns:
                    if p.search(line):
                        violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, f"API keys encontradas en: {violations}"

    def test_env_file_not_tracked(self):
        """A07:2021 — El archivo .env contiene secrets reales (tokens, API keys,
        passwords de BD). Si esta trackeado en git, cualquier persona con acceso
        al repo obtiene los secrets. Verificamos que .env esta en .gitignore y
        que git no lo trackea.
        """
        result = subprocess.run(
            ["git", "ls-files", ".env"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.stdout.strip() == "", \
            ".env esta trackeado en git — debe estar en .gitignore"

        gitignore = (REPO_ROOT / ".gitignore").read_text()
        assert ".env" in gitignore, ".env debe estar listado en .gitignore"


# =================================================================
# Grupo 2 — Injection (OWASP A03:2021)
# =================================================================


@pytest.mark.security
@pytest.mark.owasp_a03
class TestInjection:
    """OWASP A03:2021 — El codigo de produccion no debe tener patrones de injection."""

    def test_no_sql_string_formatting(self, python_source_files):
        """A03:2021 — SQL injection via f-strings permite al atacante modificar la
        estructura de la query con payloads como ' OR 1=1 --. Es la vulnerabilidad
        #3 mas explotada segun OWASP. Debe usarse parameterized queries (?).
        Buscamos f\"SELECT y f'SELECT en Python fuera de vulnerable_app/.
        """
        pattern = re.compile(r"""f["']SELECT""", re.IGNORECASE)
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if pattern.search(line):
                    violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, (
            f"SQL string formatting encontrado en: {violations}"
        )

    def test_no_shell_true_with_input(self, python_source_files):
        """A03:2021 — subprocess con shell=True interpreta el string como comando de
        shell, permitiendo inyeccion de comandos con ; | && etc. Un atacante puede
        ejecutar rm -rf / o exfiltrar datos. La correccion es pasar argumentos como
        lista sin shell=True. Buscamos shell=True en Python fuera de vulnerable_app/.
        """
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "shell=True" in line:
                    violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, f"shell=True encontrado en: {violations}"

    def test_no_pickle_loads(self, python_source_files):
        """A03:2021 — pickle.loads ejecuta codigo arbitrario durante la deserializacion.
        Un atacante puede construir un payload pickle que ejecute os.system('rm -rf /')
        al ser deserializado. La alternativa segura es json.loads() o request.get_json().
        Buscamos pickle.loads en Python fuera de vulnerable_app/.
        """
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "pickle.loads" in line:
                    violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, f"pickle.loads encontrado en: {violations}"

    def test_secure_app_uses_parameterized(self):
        """A03:2021 — Parameterized queries (placeholder ?) separan los datos de la
        estructura SQL, haciendo imposible que el input del usuario modifique la query.
        Es la defensa principal contra SQL injection recomendada por OWASP.
        Verificamos que app_secure.py usa este patron.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app_secure.py").read_text()
        assert "?" in content, \
            "app_secure.py debe usar parameterized queries con placeholder ?"
        assert "execute(" in content, \
            "app_secure.py debe usar cursor.execute() para queries parametrizadas"


# =================================================================
# Grupo 3 — Security Misconfiguration (OWASP A05:2021)
# =================================================================


@pytest.mark.security
@pytest.mark.owasp_a05
class TestSecurityConfig:
    """OWASP A05:2021 — Configuraciones seguras en Docker, Terraform e infra."""

    def test_no_debug_mode_in_production(self, python_source_files):
        """A05:2021 — Flask con debug=True expone el debugger interactivo de Werkzeug
        que permite ejecutar codigo Python arbitrario desde el browser (CWE-94).
        Solo debe estar presente en vulnerable_app/ que es intencional para la demo.
        Verificamos que ningun archivo Python de produccion lo usa.
        """
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "debug=True" in line:
                    violations.append(f"{f.relative_to(REPO_ROOT)}:{i}")
        assert not violations, (
            f"debug=True encontrado fuera de vulnerable_app/: {violations}"
        )

    def test_dockerfile_no_root(self, dockerfiles):
        """A05:2021 — Ejecutar containers como root viola el principio de minimo
        privilegio (CWE-250). Si un atacante escapa del proceso, obtiene root en
        el host. La instruccion USER en el Dockerfile fuerza ejecucion como usuario
        no-root, limitando el impacto de un compromiso.
        """
        assert len(dockerfiles) > 0, "No se encontraron Dockerfiles en el repo"
        for df in dockerfiles:
            content = df.read_text()
            assert "USER" in content, (
                f"{df.relative_to(REPO_ROOT)} no tiene instruccion USER"
            )

    def test_dockerfile_no_latest_tag(self, dockerfiles):
        """A05:2021 — El tag :latest es mutable y puede cambiar sin aviso. Un rebuild
        puede introducir vulnerabilidades nuevas o romper la aplicacion. CIS Docker
        Benchmark 4.7 requiere tags especificos con version (e.g., python:3.12-slim)
        para builds reproducibles y auditables.
        """
        pattern = re.compile(r"FROM\s+\S+:latest")
        for df in dockerfiles:
            content = df.read_text()
            assert not pattern.search(content), (
                f"{df.relative_to(REPO_ROOT)} usa :latest — debe fijar version"
            )

    def test_dockerfile_has_healthcheck(self):
        """A05:2021 — Sin HEALTHCHECK, Docker no puede detectar si la aplicacion esta
        en deadlock o crasheada. El container sigue recibiendo trafico aunque este
        muerto. CIS Docker Benchmark 4.6 requiere HEALTHCHECK en todo Dockerfile
        de produccion. Verificamos el Dockerfile hardened (openclaw).
        """
        hardened = REPO_ROOT / "docker" / "openclaw" / "Dockerfile"
        assert hardened.exists(), "docker/openclaw/Dockerfile no existe"
        content = hardened.read_text()
        assert "HEALTHCHECK" in content, (
            "docker/openclaw/Dockerfile debe tener HEALTHCHECK"
        )

    def test_terraform_no_open_ingress(self):
        """A05:2021 — Security Groups con 0.0.0.0/0 en SSH (port 22) exponen el
        servicio a todo Internet. Brute force de SSH es el ataque #1 en EC2 segun
        AWS Shield reports. SSH debe restringirse a la VPN (var.vpn_cidr), nunca
        abierto a 0.0.0.0/0. Verificamos los SGs en terraform/modules/vpc/main.tf.
        """
        vpc_tf = REPO_ROOT / "terraform" / "modules" / "vpc" / "main.tf"
        assert vpc_tf.exists(), "terraform/modules/vpc/main.tf no existe"
        content = vpc_tf.read_text()
        lines = content.splitlines()
        in_ssh_rule = False
        for line in lines:
            if "from_port" in line and "22" in line:
                in_ssh_rule = True
            if in_ssh_rule and "0.0.0.0/0" in line:
                pytest.fail(
                    "SSH (port 22) esta abierto a 0.0.0.0/0 — debe usar var.vpn_cidr"
                )
            if in_ssh_rule and "}" in line:
                in_ssh_rule = False


# =================================================================
# Grupo 4 — Cryptographic Failures (OWASP A02:2021)
# =================================================================


@pytest.mark.security
@pytest.mark.owasp_a02
class TestCryptoTransport:
    """OWASP A02:2021 — Configuraciones criptograficas modernas y seguras."""

    def test_wireguard_uses_modern_crypto(self):
        """A02:2021 — WireGuard implementa Curve25519 (ECDH), ChaCha20-Poly1305 (AEAD)
        y BLAKE2s (hash) como unica opcion — no existe cipher downgrade. Al verificar
        que los configs tienen formato WireGuard valido ([Interface] con PrivateKey),
        confirmamos criptografia moderna sin posibilidad de degradacion.
        """
        wg_dir = REPO_ROOT / "configs" / "wireguard"
        wg_configs = list(wg_dir.glob("wg0-*.conf"))
        assert len(wg_configs) >= 3, \
            f"Deben existir al menos 3 configs WireGuard, encontrados: {len(wg_configs)}"
        for cfg in wg_configs:
            content = cfg.read_text()
            assert "[Interface]" in content, \
                f"{cfg.name} no tiene seccion [Interface]"
            assert "PrivateKey" in content, \
                f"{cfg.name} no tiene PrivateKey (Curve25519)"

    def test_ssh_config_secure(self):
        """A02:2021 — Ed25519 (Curve25519) es la curva eliptica recomendada por
        Mozilla y NIST para SSH. RSA < 2048 bits es vulnerable, DSA esta deprecado,
        y ECDSA tiene riesgo de nonce-reuse attacks. Verificamos que los scripts
        de generacion de llaves usan exclusivamente Ed25519.
        """
        cert_script = REPO_ROOT / "scripts" / "generate_mtls_certs.sh"
        assert cert_script.exists(), "scripts/generate_mtls_certs.sh no existe"
        content = cert_script.read_text()
        assert "ed25519" in content.lower(), \
            "El script de certificados debe generar llaves SSH Ed25519"
        assert "ssh-keygen" in content, \
            "El script debe usar ssh-keygen para generar llaves"

    def test_no_http_urls_in_code(self, python_source_files):
        """A02:2021 — URLs con http:// transmiten datos en texto plano, vulnerables
        a man-in-the-middle (MITM). Todo trafico externo debe usar https://.
        Excluimos localhost y IPs internas (10.x, 192.168.x, 127.0.0.1) que no
        salen a la red publica.
        """
        http_external = re.compile(
            r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.)"
        )
        violations = []
        for f in python_source_files:
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if http_external.search(line):
                    violations.append(
                        f"{f.relative_to(REPO_ROOT)}:{i}: {line.strip()}"
                    )
        assert not violations, (
            f"URLs http:// externas en codigo de produccion: {violations}"
        )


# =================================================================
# Grupo 5 — Vulnerable App Detection
# Verificar que las vulnerabilidades demo existen Y que app_secure
# las corrige correctamente.
# =================================================================


@pytest.mark.security
class TestVulnerableAppDetection:
    """Verificar que la app demo tiene las vulnerabilidades esperadas
    y que la version segura las corrige."""

    def test_vulnerable_app_has_sqli(self):
        """La app vulnerable DEBE tener SQL injection (f\"SELECT) para la demo.
        Sin ella, Bandit (B608) y Semgrep no generarian findings que mostrar
        a la audiencia durante el workshop. Es material educativo intencional.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app.py").read_text()
        assert 'f"SELECT' in content or "f'SELECT" in content, \
            "app.py debe tener f-string SQL para la demo de injection"

    def test_vulnerable_app_has_cmdi(self):
        """La app vulnerable DEBE tener command injection (shell=True) para que
        Bandit detecte B602 (subprocess_popen_with_shell_equals_true) y la
        audiencia vea como se reporta en el pipeline.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app.py").read_text()
        assert "shell=True" in content, \
            "app.py debe tener shell=True para la demo de command injection"

    def test_vulnerable_app_has_pickle(self):
        """La app vulnerable DEBE tener pickle.loads para que Bandit detecte
        B301 (pickle) — insecure deserialization que permite Remote Code
        Execution (RCE) al deserializar objetos maliciosos.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app.py").read_text()
        assert "pickle.loads" in content, \
            "app.py debe tener pickle.loads para la demo de deserialization"

    def test_secure_app_no_sqli(self):
        """app_secure.py es la remediacion que se muestra como diff en el taller.
        NO debe tener f-string SQL en codigo activo — solo parameterized queries.
        Los comentarios y docstrings que explican el 'antes' se ignoran.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app_secure.py").read_text()
        for lineno, line in code_lines(content):
            assert 'f"SELECT' not in line and "f'SELECT" not in line, \
                f"app_secure.py:{lineno} tiene SQL injection en codigo activo: {line}"

    def test_secure_app_no_cmdi(self):
        """app_secure.py NO debe usar shell=True en codigo activo. La correccion
        consiste en pasar argumentos como lista a subprocess.run() y validar
        el input del usuario con regex antes de ejecutar.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app_secure.py").read_text()
        for lineno, line in code_lines(content):
            assert "shell=True" not in line, \
                f"app_secure.py:{lineno} tiene shell=True en codigo activo: {line}"

    def test_secure_app_no_pickle(self):
        """app_secure.py NO debe usar pickle.loads en codigo activo. La correccion
        reemplaza pickle por request.get_json() para deserializacion segura,
        eliminando el riesgo de Remote Code Execution.
        """
        content = (REPO_ROOT / "vulnerable_app" / "app_secure.py").read_text()
        for lineno, line in code_lines(content):
            assert "pickle.loads" not in line, \
                f"app_secure.py:{lineno} tiene pickle.loads en codigo activo: {line}"


# =================================================================
# Grupo 6 — Vulnerable and Outdated Components (OWASP A06:2021)
# =================================================================


@pytest.mark.security
@pytest.mark.owasp_a06
class TestDependencies:
    """OWASP A06:2021 — Las dependencias deben estar declaradas para ser auditables."""

    def test_requirements_exist(self):
        """A06:2021 — Sin requirements.txt, safety y pip-audit no pueden escanear
        las dependencias en busca de CVEs conocidos. El pipeline necesita este archivo
        para ejecutar el check automatico de componentes vulnerables. Verificamos
        que existe y contiene las dependencias minimas del proyecto.
        """
        req = REPO_ROOT / "requirements.txt"
        assert req.exists(), "requirements.txt no existe en la raiz del proyecto"
        content = req.read_text()
        assert len(content.strip()) > 0, "requirements.txt esta vacio"
        assert "pytest" in content, \
            "requirements.txt debe incluir pytest para el test suite"
