[![DevSecOps Pipeline](https://github.com/Jawy77/Tribu-Lab/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/Jawy77/Tribu-Lab/actions/workflows/devsecops-pipeline.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-blue.svg)](https://owasp.org/Top10/)
[![Security Checks](https://img.shields.io/badge/Security%20Checks-12-blueviolet.svg)](#-los-12-checks-de-seguridad)
[![Workshop](https://img.shields.io/badge/Workshop-500%2B%20attendees-orange.svg)](#)

# Bunker DevSecOps — 12 Security Checks Automaticos en < 10 min

### Workshop de Seguridad con AI | Comunidad Claude Anthropic Colombia | Mantishield

---

> **12 security checks automaticos en cada commit**, alineados con OWASP Top 10 2021, completando en menos de 10 minutos. Costo: **$0**.

---

> [!CAUTION]
> ## REPOSITORIO CON CODIGO INTENCIONALMENTE VULNERABLE
>
> El archivo `vulnerable_app/app.py` contiene **7 vulnerabilidades plantadas** para fines educativos:
>
> | # | Vulnerabilidad | OWASP ID | CWE |
> |---|---|---|---|
> | 1 | **SQL Injection** — f-string en query SQL | A03:2021 | CWE-89 |
> | 2 | **Command Injection** — subprocess con shell=True | A03:2021 | CWE-78 |
> | 3 | **Hardcoded Secrets** — SECRET_KEY, DATABASE_PASSWORD, API_KEY | A07:2021 | CWE-798 |
> | 4 | **Insecure Deserialization** — pickle.loads en datos del usuario | A08:2021 | CWE-502 |
> | 5 | **Path Traversal** — open() sin sanitizar ruta | A01:2021 | CWE-22 |
> | 6 | **SSRF** — urlopen sin validacion de dominio/esquema | A10:2021 | CWE-918 |
> | 7 | **Debug Mode** — Flask debug=True + bind 0.0.0.0 | A05:2021 | CWE-94 |
>
> **Los secrets son FAKE** — `sk-ant-api03-FAKE_KEY_FOR_DEMO_ONLY` no funciona en ningun servicio.
>
> **NUNCA** desplegar `vulnerable_app/` en produccion ni en redes expuestas.
>
> **Uso exclusivo**: educacion y demostracion de herramientas DevSecOps.

---

## Los 12 Checks de Seguridad

Cada push a `main` y cada Pull Request ejecuta automaticamente estos 12 checks via GitHub Actions:

| # | Check | Tool | OWASP ID | Detecta |
|---|---|---|---|---|
| 1 | Secret Scan (historial) | TruffleHog | A07:2021 | API keys/passwords en commits anteriores |
| 2 | Secret Scan (patterns) | Gitleaks | A07:2021 | Patterns de secrets en codigo actual |
| 3 | SAST Python | Bandit | A03:2021 | SQLi, CMDi, pickle, debug, hardcoded creds |
| 4 | SAST Multi-lang | Semgrep | A03:2021 | Injection en cualquier lenguaje |
| 5 | Dependency Audit | Safety / pip-audit | A06:2021 | CVEs en dependencias de Python |
| 6 | Container CVEs | Trivy | A06:2021 | Vulnerabilidades en imagen Docker |
| 7 | Dockerfile Lint | Hadolint | A05:2021 | Misconfigurations en Dockerfile |
| 8 | IaC Security | tfsec | A05:2021 | Misconfigurations en Terraform |
| 9 | IaC Policy | Checkov | A05:2021 | Compliance CIS / NIST |
| 10 | License Audit | pip-licenses | — | Licencias incompatibles en deps |
| 11 | Security Tests | Pytest (21 tests) | A04:2021 | Validaciones de seguridad en Docker, TF, crypto |
| 12 | Alert Pipeline | Telegram + Discord | — | Notificaciones real-time a canales del equipo |

> Checks 6-9 son **condicionales**: solo corren si el repo contiene Dockerfile o archivos `.tf`.

---

## Arquitectura — La Trinidad

```
                        RED PRIVADA WIREGUARD
                          10.13.13.0/24

   +-----------------+    +-----------------+    +--------------------+
   |    VPN Hub      |    |   Parrot OS     |    |    EC2-Agent       |
   |   10.13.13.1    |<-->|   10.13.13.2    |<-->|    10.13.13.4      |
   |   Gateway       |    |   Workstation   |    |   OpenClaw Bot     |
   |   NAT/FW        |    |   Claude Code   |    |   Docker + AI      |
   +-----------------+    +-----------------+    +--------------------+
          |                       |                       |
          +-----------------------+-----------------------+
                                  |
                        Split Tunneling
                  (Internet local + VPN privada)

              +-------------------------------+
              |       GitHub Actions          |
              |  Secret Scan -> SAST -> Deps  |
              |  Container -> IaC -> Notify   |
              +---------------+---------------+
                              | webhook
                              v
                 +-------------------------+
                 |   Telegram + Discord    |
                 |   Alertas real-time     |
                 +-------------------------+
```

---

## Quick Start

```bash
# 1. Clonar el repositorio
git clone https://github.com/Jawy77/Tribu-Lab.git
cd Tribu-Lab

# 2. Crear entorno virtual e instalar herramientas
python3 -m venv .venv
source .venv/bin/activate
pip install bandit semgrep safety pytest

# 3. Ejecutar los scans de seguridad
./scripts/run_security_checks.sh

# 4. Ejecutar los tests
pytest tests/ -v

# 5. (Opcional) Configurar alertas
cp .env.example .env
# Editar .env con TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL
```

### Demo en Vivo

```bash
# Abre el dashboard en un browser
cd monitoring && python3 -m http.server 8080 &
# -> http://localhost:8080/dashboard.html

# Corre el demo interactivo (presiona ENTER entre stages)
bash scripts/demo_live.sh
```

El dashboard se actualiza en tiempo real y las alertas llegan a Telegram/Discord conforme cada stage se ejecuta.

---

## Estructura del Repositorio

```
Tribu-Lab/
+-- .github/workflows/       Pipeline CI/CD con 12 security gates
|   +-- devsecops-pipeline.yml
+-- vulnerable_app/           App intencionalmente vulnerable (DEMO ONLY)
|   +-- app.py                7 vulnerabilidades plantadas
|   +-- app_secure.py         Version corregida (0 findings Medium+)
|   +-- requirements.txt
+-- monitoring/               Dashboard de monitoreo real-time
|   +-- dashboard.html        React + Tailwind (dark cybersecurity theme)
|   +-- status.json           Data que se actualiza con cada scan
+-- scripts/
|   +-- demo_live.sh          Demo interactivo paso a paso
|   +-- run_security_checks.sh  Ejecutar todos los scans localmente
|   +-- verify_bunker.sh      Health check de la infraestructura
|   +-- generate_mtls_certs.sh  Generar PKI para mTLS
|   +-- update_dashboard_status.py  Helper para actualizar dashboard
+-- skills/
|   +-- devsecops-pipeline/   Skill para Claude Code
|   +-- docker-hardening-auditor/  Skill de auditoria Docker
+-- tests/
|   +-- test_security.py      21 tests (Docker, Terraform, Crypto, SAST)
+-- terraform/                IaC para AWS (la trinidad)
+-- docker/                   Dockerfiles hardened
+-- configs/                  WireGuard, Nginx
+-- docs/                     Guias y cheatsheets
```

---

## Agenda del Taller (2 horas)

| Tiempo | Modulo | Descripcion |
|---|---|---|
| 00:00 - 00:25 | **Pipeline DevSecOps** | GitHub Actions + SAST (Bandit/Semgrep) + Trivy + tfsec |
| 00:25 - 00:50 | **Skills para Claude Code** | Crear, auditar y empaquetar skills |
| 00:50 - 01:15 | **El Bunker del Bot** | Docker hardening, OpenClaw aislado, WireGuard |
| 01:15 - 01:35 | **Criptografia Aplicada** | mTLS, Ed25519, TLS 1.3, zero-trust |
| 01:35 - 02:00 | **Demo End-to-End + Q&A** | Pipeline completo + alertas en vivo |

---

## Herramientas Utilizadas

| Categoria | Herramientas |
|---|---|
| **CI/CD** | GitHub Actions |
| **SAST** | Bandit, Semgrep |
| **Secret Scanning** | TruffleHog, Gitleaks |
| **Dependencies** | Safety, pip-audit |
| **Containers** | Trivy, Hadolint, Docker |
| **IaC** | tfsec, Checkov, Terraform |
| **Testing** | Pytest |
| **Alerting** | Telegram Bot API, Discord Webhooks |
| **Monitoring** | Dashboard custom (React + Tailwind) |
| **AI Copilot** | Claude Code |
| **Network** | WireGuard VPN, Nginx mTLS |
| **Crypto** | TLS 1.3, Ed25519, X.509 |

---

## Nota de Seguridad

> [!IMPORTANT]
> - **NUNCA** subas llaves privadas, tokens, o archivos `.env` al repositorio
> - Este repo usa `.gitignore` estricto y secrets de GitHub Actions
> - Las llaves y certificados en `crypto/` son **ejemplos** — genera los tuyos propios
> - El pipeline usa `--only-verified` en TruffleHog para reducir falsos positivos
> - Container e IaC scans son condicionales (solo si hay Dockerfile / .tf)

---

## Licencia

MIT — Hecho por [Mantishield](https://mantishield.com) para la Comunidad Tribu Colombia y Latam.

## Creditos

- **Jawy** — Mantishield / Cybersecurity Researcher
- **Comunidad Tribu AI Colombia**
- **OpenClaw Project**

---

<p align="center">
  <sub>Bunker DevSecOps &middot; 12 Checks &middot; OWASP Top 10 &middot; $0 cost &middot; < 10 min</sub>
</p>
