# 🛡️ Búnker DevSecOps Distribuido — Masterclass

## Comunidad Claude Anthropic Colombia 🇨🇴

> **Taller práctico de 2 horas**: Cómo construir un pipeline DevSecOps seguro usando Claude Code, GitHub Actions, Terraform, Docker, OpenClaw Bot, y criptografía aplicada — todo conectado a través de una red privada soberana con WireGuard.

---

## 🎯 ¿Qué vamos a construir?

Una infraestructura de seguridad distribuida donde:

1. **Ningún servicio está expuesto a Internet** — todo viaja por VPN WireGuard
2. **Un bot de AI (OpenClaw)** revisa código automáticamente desde un búnker aislado en AWS
3. **El pipeline CI/CD** escanea vulnerabilidades en cada push
4. **La comunicación entre nodos** está cifrada con Mutual TLS + WireGuard
5. **Claude Code** actúa como copiloto de seguridad en todo el proceso

## 🏗️ Arquitectura — "La Trinidad"

```
┌─────────────────────────────────────────────────────────────────┐
│                    RED PRIVADA WIREGUARD                        │
│                      10.13.13.0/24                              │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  VPN Hub     │    │  Parrot OS   │    │  EC2-Agent       │  │
│  │  10.13.13.1  │◄──►│  10.13.13.2  │◄──►│  10.13.13.4      │  │
│  │  Gateway     │    │  Workstation │    │  OpenClaw Bot    │  │
│  │  NAT/FW      │    │  Claude Code │    │  Docker + AI     │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│         │                    │                     │            │
│         └────────────────────┼─────────────────────┘            │
│                              │                                  │
│                    Split Tunneling                               │
│              (Internet local + VPN privada)                      │
└─────────────────────────────────────────────────────────────────┘

          ┌─────────────────────────────────┐
          │        GitHub Actions           │
          │   SAST → Container Scan → Deploy│
          │   Bandit │ Semgrep │ Trivy      │
          └─────────────┬───────────────────┘
                        │ webhook
                        ▼
              ┌───────────────────┐
              │   Telegram Bot    │
              │   /review command │
              └───────────────────┘
```

## 📋 Agenda del Taller (2 horas)

| Tiempo | Módulo | Descripción |
|--------|--------|-------------|
| 00:00 - 00:25 | **Módulo 1**: Pipeline DevSecOps | GitHub Actions + SAST (Bandit/Semgrep) + Trivy + tfsec |
| 00:25 - 00:50 | **Módulo 2**: Skills para Claude Code | Crear, auditar y empaquetar skills para el Marketplace |
| 00:50 - 01:15 | **Módulo 3**: El Búnker del Bot | Docker hardening, OpenClaw aislado, WireGuard |
| 01:15 - 01:35 | **Módulo 4**: Criptografía Aplicada | mTLS, Ed25519, TLS 1.3, zero-trust |
| 01:35 - 02:00 | **Módulo 5**: Demo End-to-End + Q&A | Pipeline completo + `/review` desde Telegram |

## 🛠️ Prerequisitos

```bash
# Herramientas necesarias
- Git
- Docker & Docker Compose
- Terraform >= 1.5
- Python >= 3.10
- Claude Code CLI (npm install -g @anthropic-ai/claude-code)
- WireGuard tools
- OpenSSL
```

## 🚀 Quick Start

```bash
# 1. Clonar el repositorio
git clone https://github.com/mantishield/devsecops-bunker-workshop.git
cd devsecops-bunker-workshop

# 2. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus API keys

# 3. Levantar la infraestructura local (para práctica)
docker compose up -d

# 4. Ejecutar los tests de seguridad
./scripts/run_security_checks.sh

# 5. Verificar la conexión del búnker
./scripts/verify_bunker.sh
```

## 📁 Estructura del Repositorio

```
devsecops-bunker-workshop/
├── .github/workflows/       # CI/CD pipelines con security gates
│   ├── devsecops-pipeline.yml
│   └── container-scan.yml
├── docker/
│   ├── openclaw/            # Dockerfile hardened para OpenClaw
│   └── app/                 # App de ejemplo para escanear
├── terraform/
│   └── modules/             # IaC para la trinidad en AWS
├── scripts/                 # Automatización y demos
├── crypto/                  # Certificados mTLS y llaves
├── configs/                 # WireGuard, Nginx, etc.
├── tests/                   # Security tests (21 tests)
├── skills/
│   └── devsecops-pipeline/  # 🆕 Skill para Claude Code (Marketplace ready)
│       ├── SKILL.md
│       ├── references/
│       └── evals/
├── dist/                    # 🆕 Skill empaquetado (.skill)
├── docs/
│   ├── CHEATSHEET.md        # Comandos para la demo en vivo
│   └── GUIDE-CREATING-SKILLS.md  # 🆕 Guía didáctica de skills
└── vulnerable_app/          # App intencionalmente vulnerable (para demo)
```

## 🔐 Nota de Seguridad

> **NUNCA** subas llaves privadas, tokens, o archivos `.env` al repositorio.
> Este repo usa `.gitignore` estricto y secrets de GitHub Actions.
> Las llaves y certificados en `crypto/` son **ejemplos** — genera los tuyos propios.

## 📜 Licencia

MIT — Hecho con 🔒 por [Mantishield](https://mantishield.com) para la Comunidad Claude Anthropic Colombia.

## 🙏 Créditos

- **Jawy** — Mantishield / Cybersecurity Researcher
- **Comunidad Tribu AI Colombia**
- **OpenClaw Project**
