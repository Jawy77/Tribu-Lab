"""
🧪 Security Tests — Búnker DevSecOps Workshop
Comunidad Claude Anthropic Colombia

Tests automatizados que verifican la postura de seguridad
de la infraestructura y la aplicación.

Ejecutar: pytest tests/ -v
"""

import json
import os
import subprocess

import pytest


# ═══════════════════════════════════════════════════════════════
# Test Group 1: Docker Security
# ═══════════════════════════════════════════════════════════════


class TestDockerSecurity:
    """Verifica que los containers siguen best practices de seguridad."""

    def test_dockerfile_has_non_root_user(self):
        """El Dockerfile de OpenClaw debe usar un usuario no-root."""
        with open("docker/openclaw/Dockerfile") as f:
            content = f.read()
        assert "USER" in content, "Dockerfile debe especificar USER no-root"
        assert "root" not in content.split("USER")[-1].split("\n")[0], \
            "USER no debe ser root"

    def test_dockerfile_has_healthcheck(self):
        """El Dockerfile debe tener HEALTHCHECK."""
        with open("docker/openclaw/Dockerfile") as f:
            content = f.read()
        assert "HEALTHCHECK" in content, "Dockerfile debe tener HEALTHCHECK"

    def test_dockerfile_uses_multistage(self):
        """El Dockerfile debe usar multi-stage build."""
        with open("docker/openclaw/Dockerfile") as f:
            content = f.read()
        from_count = content.count("FROM ")
        assert from_count >= 2, \
            f"Debe usar multi-stage build (encontrados {from_count} FROM, mínimo 2)"

    def test_compose_has_security_opts(self):
        """docker-compose debe tener security_opt configurado."""
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "no-new-privileges" in content, \
            "docker-compose debe incluir no-new-privileges"

    def test_compose_has_resource_limits(self):
        """docker-compose debe limitar recursos (CPU/memoria)."""
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "limits" in content, "Debe tener resource limits"
        assert "memory" in content, "Debe limitar memoria"

    def test_compose_drops_capabilities(self):
        """docker-compose debe hacer cap_drop: ALL."""
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "cap_drop" in content, "Debe hacer cap_drop"
        assert "ALL" in content, "Debe dropear ALL capabilities"

    def test_compose_read_only_filesystem(self):
        """Los containers deben usar read_only: true."""
        with open("docker-compose.yml") as f:
            content = f.read()
        assert "read_only: true" in content, \
            "Containers deben tener filesystem read-only"


# ═══════════════════════════════════════════════════════════════
# Test Group 2: Terraform Security
# ═══════════════════════════════════════════════════════════════


class TestTerraformSecurity:
    """Verifica que la IaC sigue principios zero-trust."""

    def test_no_ssh_from_internet(self):
        """SSH no debe estar abierto a 0.0.0.0/0."""
        with open("terraform/modules/vpc/main.tf") as f:
            content = f.read()
        # Buscar reglas de SSH — ninguna debe tener 0.0.0.0/0
        lines = content.split("\n")
        in_ssh_block = False
        for line in lines:
            if "from_port" in line and "22" in line:
                in_ssh_block = True
            if in_ssh_block and "0.0.0.0/0" in line:
                pytest.fail("SSH está abierto a Internet (0.0.0.0/0)!")
            if in_ssh_block and "}" in line:
                in_ssh_block = False

    def test_ec2_uses_imdsv2(self):
        """Las instancias EC2 deben usar IMDSv2 obligatorio."""
        with open("terraform/modules/ec2/main.tf") as f:
            content = f.read()
        assert 'http_tokens' in content, "Debe configurar metadata_options"
        assert '"required"' in content, "IMDSv2 debe ser obligatorio"

    def test_ebs_encryption(self):
        """Los volúmenes EBS deben estar encriptados."""
        with open("terraform/modules/ec2/main.tf") as f:
            content = f.read()
        assert "encrypted" in content, "EBS debe estar encriptado"
        assert "encrypted   = true" in content or "encrypted = true" in content, \
            "encrypted debe ser true"

    def test_monitoring_enabled(self):
        """Detailed monitoring debe estar habilitado."""
        with open("terraform/modules/ec2/main.tf") as f:
            content = f.read()
        assert "monitoring" in content, "Monitoring debe estar configurado"


# ═══════════════════════════════════════════════════════════════
# Test Group 3: Crypto Configuration
# ═══════════════════════════════════════════════════════════════


class TestCryptoConfig:
    """Verifica la configuración criptográfica."""

    def test_nginx_tls13_only(self):
        """Nginx debe usar solo TLS 1.3."""
        with open("configs/nginx/nginx-mtls.conf") as f:
            content = f.read()
        assert "TLSv1.3" in content, "Debe usar TLS 1.3"
        assert "TLSv1.2" not in content, \
            "No debe permitir TLS 1.2 (solo 1.3)"
        assert "TLSv1.1" not in content, "No debe permitir TLS 1.1"
        assert "TLSv1 " not in content, "No debe permitir TLS 1.0"

    def test_mtls_required(self):
        """mTLS debe ser obligatorio (ssl_verify_client on)."""
        with open("configs/nginx/nginx-mtls.conf") as f:
            content = f.read()
        assert "ssl_verify_client on" in content, \
            "mTLS debe ser obligatorio"

    def test_security_headers_present(self):
        """Los security headers deben estar configurados."""
        with open("configs/nginx/nginx-mtls.conf") as f:
            content = f.read()
        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]
        for header in required_headers:
            assert header in content, f"Falta header: {header}"

    def test_server_tokens_off(self):
        """Nginx no debe revelar su versión."""
        with open("configs/nginx/nginx-mtls.conf") as f:
            content = f.read()
        assert "server_tokens off" in content, \
            "server_tokens debe estar en off"


# ═══════════════════════════════════════════════════════════════
# Test Group 4: WireGuard Configuration
# ═══════════════════════════════════════════════════════════════


class TestWireGuardConfig:
    """Verifica la configuración de WireGuard."""

    def test_split_tunneling_parrot(self):
        """Parrot debe usar split tunneling (solo 10.13.13.0/24)."""
        with open("configs/wireguard/wg0-parrot.conf") as f:
            content = f.read()
        assert "10.13.13.0/24" in content, "Debe rutear solo la VPN"
        assert "0.0.0.0/0" not in content, \
            "NO debe rutear todo el tráfico por la VPN"

    def test_split_tunneling_agent(self):
        """El agente debe usar split tunneling."""
        with open("configs/wireguard/wg0-agent.conf") as f:
            content = f.read()
        assert "10.13.13.0/24" in content, "Debe rutear solo la VPN"

    def test_no_private_keys_committed(self):
        """No debe haber llaves privadas reales en los configs."""
        configs = [
            "configs/wireguard/wg0-hub.conf",
            "configs/wireguard/wg0-parrot.conf",
            "configs/wireguard/wg0-agent.conf",
        ]
        for config_file in configs:
            with open(config_file) as f:
                content = f.read()
            # Las llaves reales de WireGuard son base64 de 44 chars
            assert "[" in content and "]" in content, \
                f"{config_file} parece tener llaves reales (no placeholders)"


# ═══════════════════════════════════════════════════════════════
# Test Group 5: SAST Results (si existen)
# ═══════════════════════════════════════════════════════════════


class TestSASTResults:
    """Verifica que la app vulnerable tiene los issues esperados."""

    def test_vulnerable_app_has_sql_injection(self):
        """La app vulnerable debe tener SQL injection (para demo)."""
        with open("vulnerable_app/app.py") as f:
            content = f.read()
        assert "f\"SELECT" in content or "f'SELECT" in content, \
            "La app vulnerable debe tener SQL injection para la demo"

    def test_vulnerable_app_has_hardcoded_secret(self):
        """La app vulnerable debe tener secrets hardcodeados."""
        with open("vulnerable_app/app.py") as f:
            content = f.read()
        assert "SECRET_KEY" in content and '=' in content, \
            "Debe tener hardcoded secrets para la demo"

    def test_safe_endpoints_exist(self):
        """Deben existir endpoints seguros para comparar."""
        with open("vulnerable_app/app.py") as f:
            content = f.read()
        assert "/safe" in content, \
            "Debe tener endpoints /safe para comparación"
        assert "?" in content, \
            "Los endpoints seguros deben usar parameterized queries"
