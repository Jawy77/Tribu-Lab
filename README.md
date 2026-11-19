[![Security Gate](https://github.com/Jawy77/auditgate/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/Jawy77/auditgate/actions/workflows/devsecops-pipeline.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Actions pinned by SHA](https://img.shields.io/badge/actions-pinned%20by%20SHA-informational.svg)](src/auditgate/rules/github-actions/auditgate-actions.yml)
[![Releases: SBOM + SLSA + cosign](https://img.shields.io/badge/releases-SBOM%20%C2%B7%20SLSA%20%C2%B7%20cosign-informational.svg)](.github/workflows/release.yml)

<h1 align="center">Auditgate</h1>

<p align="center"><strong>Plataforma de seguridad para CI/CD, open source: un gate determinista que bloquea solo lo nuevo, y agentes de IA que encuentran, priorizan y ayudan a codificar, sin decidir nunca un merge.</strong></p>

<p align="center"><em>Open-source CI/CD security platform: a deterministic gate that blocks only what's new, plus AI agents that find, triage and help codify, and never decide a merge.</em></p>

<p align="center"><code>El agente descubre y prioriza. El determinismo bloquea.</code></p>

---

## Por qué existe

La mayoría de los pipelines de seguridad **alertan, pero no bloquean**: corren 12 escáneres con
`continue-on-error` y `main` sigue en verde con vulnerabilidades adentro. Y el propio pipeline suele
ser superficie de ataque: actions sin fijar, tokens con permisos de más y secretos de larga duración.

Auditgate aplica *Security Platform Engineering* (la seguridad como producto interno, un *paved road*
que cada repo hereda) y la metodología **Find → Extract → Codify → Scale** del GitHub Security Lab:

| Fase | Quién | En Auditgate |
|---|---|---|
| **Find** | Agente | Auditoría semanal con taskflow (map → hunt → refute → extract) → issue `needs-validation` |
| **Validate** | Humano | Reproduce con PoC. Ningún hallazgo de un agente bloquea sin esto |
| **Extract** | Humano + agente | Patrón generalizable, no el bug puntual |
| **Codify** | Regla | Regla Semgrep + fixture con tests en [`src/auditgate/rules/`](src/auditgate/rules/). El gate exige que pasen |
| **Scale** | Plataforma | El reusable workflow lleva la regla a cada repo que lo consume |

## Qué incluye

| Pieza | Archivo | Rol |
|---|---|---|
| Paved road | [`security-platform.yml`](.github/workflows/security-platform.yml) | Reusable workflow; un repo lo consume con unas 10 líneas |
| Gate determinista | job `🚦 Security Gate` | Único check requerido. Bloquea solo lo **nuevo** (diff-aware) |
| Reglas con tests | [`src/auditgate/rules/`](src/auditgate/rules/) | Python/Flask y supply chain de GitHub Actions |
| Triage con IA | [`src/auditgate/triage.py`](src/auditgate/triage.py) | Comenta TP/FP, alcanzabilidad y fix en el PR. **Nunca bloquea**. Claude, Grok, OpenAI o compatible |
| CLI | [`src/auditgate/cli.py`](src/auditgate/cli.py) | `auditgate scan` (el gate en tu máquina) · `init / set-key / doctor` |
| Agente de auditoría | [`agents/taskflows/`](agents/taskflows/) | La metodología en YAML; el modelo es intercambiable |
| Sin API keys | [`docs/WIF-SETUP.md`](docs/WIF-SETUP.md) | Los agentes se autentican con el OIDC de GitHub (Workload Identity Federation) |
| Supply chain | [`release.yml`](.github/workflows/release.yml) | SHA pinning, mínimo privilegio, SBOM, provenance SLSA, cosign keyless |
| Política | [`SECURITY.md`](SECURITY.md) | Reglas para reportes, incluidos los asistidos por IA |

Arquitectura, política del gate y guardrails de los agentes: [`docs/PLATFORM-V2.md`](docs/PLATFORM-V2.md).

## Dos formas de usarlo, un solo motor

| | Dónde corre | Quién lo ejecuta | Para qué |
|---|---|---|---|
| **En el repo** (GitHub Actions) | Servidores de GitHub | GitHub, en cada PR | El gate oficial: **bloquea el merge** |
| **En tu terminal** (CLI) | Tu máquina | Tú o tu agente (Claude Code, Cursor…) | El **mismo gate antes del push** + instalar y configurar |

El CLI y el workflow ejecutan el mismo código y las mismas reglas: si `auditgate scan` pasa
en tu máquina, el PR pasa en GitHub.

```bash
auditgate scan                 # evalúa tus commits nuevos contra la rama base (exit 0 pasa · 1 bloquea · 2 error)
auditgate scan --json          # salida estructurada para agentes y scripts
auditgate scan --checks sast   # solo un control: secrets, sast, deps, actions
```

`scan` corre en un worktree temporal de tu último commit, así que evalúa lo que llegará al PR
y nunca toca tus archivos. Usa las mismas herramientas que CI, instaladas aparte:
`brew install gitleaks osv-scanner` y `pipx install semgrep`. Si falta una, ese
control se omite y lo avisa; con `--strict`, falta = error.

### Lenguajes

| Control | Cobertura |
|---|---|
| Secretos, workflows de GitHub Actions, contenedor | Cualquier lenguaje |
| **Dependencias** (osv-scanner) | npm, PyPI, Go, Maven/Gradle, crates.io, RubyGems, Packagist, NuGet… con transitivas |
| **SAST** (Semgrep) | Un set de reglas por cada lenguaje detectado: Python, JavaScript, TypeScript, Go, Java, Kotlin, Ruby, PHP, C#, Rust, C/C++, Scala, Swift |

Reglas propias de Auditgate (MIT, con tests): Python/Flask y Node.js. Para el resto se usa el set
del registro de Semgrep de ese lenguaje, que tu Semgrep descarga para tu propio uso (Auditgate no
lo redistribuye; `--no-registry` lo desactiva).

**El gate nunca da un verde engañoso:** si encuentra código en un lenguaje sin reglas (por ejemplo
Dart), lo avisa en el PR, en `auditgate scan` y en `auditgate doctor`; con `--strict`, es un error.

**Para agentes:** agrega a tu `CLAUDE.md` (o equivalente) algo como *"antes de abrir un PR,
corre `auditgate scan --json` y corrige todo lo que tenga `status: blocked`"*. El agente
recibe la misma política que el gate y no puede saltársela: el merge lo sigue decidiendo CI.

## Empezar en 1 minuto

```bash
pipx install "git+https://github.com/Jawy77/auditgate"
cd tu-repo
auditgate init      # elige el modelo: Claude, Grok, OpenAI o uno compatible (Ollama, OpenRouter...)
git add .github/workflows/auditgate.yml && git commit -m "ci: instala Auditgate" && git push
```

- **Tu modelo, tu llave.** La llave se pide sin mostrarla, viaja por stdin y queda cifrada en
  el Environment `auditgate` de GitHub: solo el job del agente la recibe.
  Detalle en [`docs/LLM-PROVIDERS.md`](docs/LLM-PROVIDERS.md).
- **Sin modelo también funciona.** El gate determinista no depende de la IA; el agente es opcional.
- **Con Claude puedes no tener llave:** Workload Identity Federation ([`docs/WIF-SETUP.md`](docs/WIF-SETUP.md)).

## Origen

Auditgate nació como **Bunker DevSecOps**, el workshop de Tribu, Hacklab Bogotá y Ethereum Bogotá
con Mantishield (más de 500 asistentes). El material del workshop sigue en este repo como demo viva
de la plataforma.

> [!CAUTION]
> **Este repo incluye código intencionalmente vulnerable para la demo.**
> `vulnerable_app/app.py` tiene 7 vulnerabilidades plantadas (SQLi, command injection, secretos
> hardcodeados, deserialización insegura, path traversal, SSRF y debug mode). Los secretos son
> FAKE. **Nunca** despliegues `vulnerable_app/` en producción ni en redes expuestas.

---

## Los 12 Checks de Seguridad (v1, referencia histórica)

Cada push a `main` y cada Pull Request ejecuta automaticamente estos 12 checks via GitHub Actions:

| # | Check | Tool | OWASP ID | Detecta |
|---|---|---|---|---|
| 1 | Secret Scan (historial) | TruffleHog | A07:2021 | API keys y passwords en commits anteriores |
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

> [!NOTE]
> Checks 6-9 son **condicionales**: solo corren si el repo contiene Dockerfile o archivos `.tf`. El pipeline detecta automaticamente su presencia.

---

## Arquitectura — La Trinidad

```
+=====================================================================+
|                     RED PRIVADA WIREGUARD                           |
|                       10.13.13.0/24                                 |
|                                                                     |
|  +-------------------+  +-------------------+  +-----------------+  |
|  |                   |  |                   |  |                 |  |
|  |     VPN HUB       |  |    PARROT OS      |  |   EC2-AGENT     |  |
|  |    10.13.13.1     |  |    10.13.13.2     |  |   10.13.13.4    |  |
|  |                   |  |                   |  |                 |  |
|  |  WireGuard GW     |  |  Claude Code      |  |  OpenClaw Bot   |  |
|  |  NAT / Firewall   |  |  Bandit + Semgrep |  |  Docker Engine  |  |
|  |  Nginx mTLS       |  |  Security Audit   |  |  Trivy Scanner  |  |
|  |                   |  |                   |  |                 |  |
|  +--------+----------+  +--------+----------+  +-------+---------+  |
|           |                      |                      |           |
|           |    WireGuard :51820  |    WireGuard :51820   |           |
|           +----------------------+----------------------+           |
|                                  |                                  |
|                        Split Tunneling                              |
|                  (Internet local + VPN privada)                     |
+=====================================================================+
                                   |
                                   | git push / PR
                                   v
                  +================================+
                  |       GITHUB ACTIONS            |
                  |                                |
                  |  [Secret Scan] --> [SAST]      |
                  |       |              |         |
                  |       v              v         |
                  |  [Dep Check] --> [Build]       |
                  |       |              |         |
                  |       v              v         |
                  |  [Container] --> [IaC Scan]    |
                  |       |              |         |
                  |       v              v         |
                  |     [Tests] --> [Notify]       |
                  +===============+================+
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
          +-----------------+         +-----------------+
          |   TELEGRAM      |         |    DISCORD      |
          |   Bot Alert     |         |   Webhook Embed |
          |   (real-time)   |         |   (green/red)   |
          +-----------------+         +-----------------+
```

---

## Quick Start

```bash
git clone https://github.com/Jawy77/auditgate.git
cd auditgate
pip install -r requirements.txt

# Ver las vulnerabilidades
bandit -r vulnerable_app/ -ll

# Ejecutar tests
pytest tests/ -v

# Demo interactivo completo
bash scripts/demo_live.sh

# Para pipeline en GitHub Actions: haz fork y configura secrets
```

### Demo en Vivo (2 terminales)

```bash
# Terminal 1 — Dashboard (dejar abierto)
cd monitoring && python3 -m http.server 8080
# Abrir en browser: http://localhost:8080/dashboard.html

# Terminal 2 — Demo interactivo
bash scripts/demo_live.sh
# Presiona ENTER para avanzar entre cada stage
# Las alertas llegan a Telegram/Discord en tiempo real
# El dashboard se actualiza cada 10 segundos automaticamente
```

---

## Configuracion para tu propio Bunker

El pipeline necesita 3 secrets en GitHub para enviar notificaciones. Sin ellos el pipeline funciona igual, pero los stages de alerta se saltan silenciosamente.

### Paso 1 — Crear un Bot de Telegram

```
1. Abre Telegram y busca @BotFather
2. Envia /newbot
3. Asigna un nombre: "DevSecOps Bunker Bot"
4. Asigna un username: tu_bunker_bot
5. BotFather te devuelve el token:
   -> 7123456789:AAF1xxxxxxxxxxxxxxxxxxxxxxxxxxx
6. Guarda ese valor como TELEGRAM_BOT_TOKEN
```

### Paso 2 — Obtener el Chat ID de Telegram

```
1. Crea un grupo en Telegram o usa uno existente
2. Agrega tu bot al grupo
3. Envia cualquier mensaje al grupo
4. Abre en un browser:
   -> https://api.telegram.org/bot<TU_TOKEN>/getUpdates
5. Busca "chat":{"id":-100XXXXXXXXXX}
6. Ese numero negativo es tu TELEGRAM_CHAT_ID
```

### Paso 3 — Crear un Webhook de Discord

```
1. Abre Discord y ve al canal donde quieres las alertas
2. Click en el engranaje del canal -> Integraciones -> Webhooks
3. Click "Nuevo Webhook"
4. Asigna nombre: "Bunker DevSecOps"
5. Click "Copiar URL del Webhook"
6. Esa URL es tu DISCORD_WEBHOOK_URL
   -> https://discord.com/api/webhooks/123456789/ABCxyz...
```

### Paso 4 — Configurar en GitHub

```
1. Ve a tu fork: github.com/<tu-user>/auditgate
2. Settings -> Secrets and variables -> Actions
3. Click "New repository secret" tres veces:
```

| Secret Name | Valor | Ejemplo |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Token del paso 1 | `7123456789:AAF1xxx...` |
| `TELEGRAM_CHAT_ID` | Chat ID del paso 2 | `-1001234567890` |
| `DISCORD_WEBHOOK_URL` | URL del paso 3 | `https://discord.com/api/webhooks/...` |

### Paso 5 — Para demo local (opcional)

```bash
cp .env.example .env
nano .env
# Pega los mismos 3 valores
# El script demo_live.sh los lee automaticamente
```

---

## Estructura del Repositorio

```
auditgate/
|
+-- .github/workflows/
|   +-- devsecops-pipeline.yml       12 security gates automaticos
|
+-- vulnerable_app/                   DEMO ONLY - codigo vulnerable
|   +-- app.py                        7 vulnerabilidades plantadas (OWASP Top 10)
|   +-- app_secure.py                 Version corregida (0 findings Medium+)
|   +-- requirements.txt              Dependencias con 1 CVE conocido
|
+-- monitoring/
|   +-- dashboard.html                Panel real-time (React 18 + Tailwind)
|   +-- status.json                   Estado del pipeline (auto-refresh 10s)
|
+-- scripts/
|   +-- demo_live.sh                  Demo interactivo para audiencia en vivo
|   +-- run_security_checks.sh        Ejecutar los 12 checks localmente
|   +-- update_dashboard_status.py    Actualizar dashboard en tiempo real
|   +-- verify_bunker.sh              Health check de la infraestructura VPN
|   +-- generate_mtls_certs.sh        Generar PKI completa para mTLS
|
+-- skills/
|   +-- devsecops-pipeline/           Skill de Claude Code (pipeline audit)
|   +-- docker-hardening-auditor/     Skill de Claude Code (Docker CIS)
|   +-- package_skill.py              Empaquetador de skills (.skill)
|   +-- quick_validate.py             Validador de estructura de skills
|
+-- tests/
|   +-- test_security.py              21 tests: Docker, Terraform, Crypto, SAST
|
+-- terraform/                        IaC para AWS (la trinidad)
|   +-- main.tf
|   +-- modules/
|
+-- docker/                           Dockerfiles hardened
|   +-- app/
|   +-- openclaw/
|
+-- configs/                          Configuraciones de red
|   +-- wireguard/                    Peers VPN (Hub, Parrot, Agent)
|   +-- nginx/                        Reverse proxy con mTLS
|
+-- docs/
|   +-- CHEATSHEET.md                 Comandos rapidos para el taller
|   +-- GUIDE-CREATING-SKILLS.md      Guia para crear skills de Claude Code
```

---

## Agenda del Taller (2 horas)

| Tiempo | Modulo | Que se hace |
|---|---|---|
| 00:00 - 00:25 | **Pipeline DevSecOps** | Configurar GitHub Actions con Bandit, Semgrep, Trivy, tfsec. Ver alertas llegar a Telegram y Discord. |
| 00:25 - 00:50 | **Skills para Claude Code** | Crear un skill desde cero, validarlo, empaquetarlo como `.skill` y probarlo. |
| 00:50 - 01:15 | **El Bunker del Bot** | Docker hardening con CIS Benchmark, OpenClaw aislado en VPN, WireGuard split tunneling. |
| 01:15 - 01:35 | **Criptografia Aplicada** | Generar CA propia, certificados mTLS, Ed25519 para SSH, TLS 1.3 en Nginx. |
| 01:35 - 02:00 | **Demo End-to-End + Q&A** | Ejecutar `demo_live.sh` completo con dashboard en pantalla y alertas en tiempo real. |

---

## Stack Tecnologico

| Capa | Tecnologias |
|---|---|
| **AI y Copiloto** | Claude Code, OpenClaw Bot |
| **CI/CD** | GitHub Actions |
| **SAST** | Bandit (Python), Semgrep (multi-lenguaje) |
| **Secret Scanning** | TruffleHog (historial git), Gitleaks (patterns) |
| **Dependency Audit** | Safety, pip-audit |
| **Container Security** | Trivy (CVEs), Hadolint (Dockerfile lint) |
| **IaC Security** | tfsec (Terraform), Checkov (CIS/NIST compliance) |
| **Testing** | Pytest (21 security tests) |
| **Alerting** | Telegram Bot API, Discord Webhooks |
| **Monitoring** | Dashboard custom React 18 + Tailwind CSS |
| **Network** | WireGuard VPN (split tunneling), Nginx con mTLS |
| **Crypto** | TLS 1.3, Ed25519, X.509, Mutual TLS |
| **IaC** | Terraform (AWS), Docker, Docker Compose |
| **Lenguaje** | Python 3.10+ |

---

## Nota de Seguridad

> [!IMPORTANT]
> Este repositorio es **exclusivamente educativo**. El directorio `vulnerable_app/` existe para demostrar como las herramientas DevSecOps detectan vulnerabilidades reales. Todos los secrets incluidos en el codigo son valores falsos que no funcionan en ningun servicio. Las llaves y certificados en `crypto/` son ejemplos generados para el taller. El pipeline usa `--only-verified` en TruffleHog para reducir falsos positivos. Los scans de Container e IaC son condicionales y solo corren si el repo contiene Dockerfile o archivos `.tf`.

---

## Creditos

| Rol | Nombre |
|---|---|
| **Autor y Facilitador** | Jawy Romero ([@hackwy](https://github.com/Jawy77)) |
| **Organizacion** | [Mantishield](https://mantishield.com) |
| **Comunidad** | Tribu, Hacklab Bogota, Ethereum Bogota |
| **Proyecto OpenClaw** | Bot de seguridad aislado en VPN |

---

## Licencia

```
MIT License

Copyright (c) 2026 Jawy Romero / Mantishield

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una
copia de este software y los archivos de documentacion asociados, para
utilizar el Software sin restriccion, incluyendo sin limitacion los derechos
de usar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar
y/o vender copias del Software.

NOTA EDUCATIVA: Este repositorio contiene codigo intencionalmente vulnerable
con fines de ensenanza. El uso de vulnerable_app/ fuera de un entorno
controlado de laboratorio es bajo responsabilidad exclusiva del usuario.
Los autores no se hacen responsables de danos derivados del mal uso del
codigo vulnerable incluido en este repositorio.
```

---

<p align="center">
  <strong>Bunker DevSecOps</strong><br>
  <sub>12 Checks | OWASP Top 10 | $0 cost | < 10 min | 500+ attendees</sub><br>
  <sub>Hecho con seguridad por <a href="https://github.com/Jawy77">@hackwy</a> para la comunidad</sub>
</p>

<!-- Pipeline verified: 2026-02-19 22:55 UTC -->
