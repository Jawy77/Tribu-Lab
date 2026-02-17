# Security Stack — Bunker DevSecOps

> Documento de referencia para CISO, auditores y equipos de seguridad.
> Cubre la arquitectura de agentes, mTLS, herramientas implementadas vs pendientes, y meta-seguridad del pipeline.

**Proyecto:** Bunker DevSecOps Workshop — Mantishield
**Autor:** Jawy Romero (@hackwy)
**Ultima revision:** 2026-02-19
**Clasificacion:** Interno — Uso educativo

---

## 1. Mapa de Agentes de Seguridad

El Bunker opera con un modelo multi-agente donde cada agente tiene un rol especifico, un scope limitado, y opera en una fase distinta del SDLC.

### 1.1 Tabla de Agentes

| Agente | Rol | Donde Corre | Que Asegura | Fase SDLC |
|---|---|---|---|---|
| **Claude Code** | Analisis de codigo, generacion de fixes, crear skills | Parrot OS (10.13.13.2) | Codigo fuente | Build-time |
| **Red Queen (OpenClaw)** | Ejecucion remota, health checks, scans on-demand | EC2 Virginia (Docker) 10.13.13.4 | Infraestructura + runtime | Runtime |
| **GitHub Actions** | Pipeline CI/CD automatizado (12 checks) | GitHub Cloud | Cada commit y PR | CI-time |
| **GitHub Copilot** | Code review, sugerencias seguras en IDE | VS Code / Kiro (local) | Codigo en tiempo de escritura | Design-time |
| **Trivy** | Container scanning (CVEs en imagenes) | CI/CD (GitHub Actions) | Imagenes Docker | CI-time |
| **Bandit** | SAST para Python | CI/CD + Parrot OS local | Codigo Python | CI-time + Build-time |
| **Semgrep** | SAST multi-lenguaje | CI/CD + Parrot OS local | Codigo Python/JS/Go/etc | CI-time + Build-time |
| **TruffleHog** | Secret scanning en historial git | CI/CD | Historial de commits | CI-time |
| **Gitleaks** | Secret scanning en codigo actual | CI/CD | Codigo fuente actual | CI-time |
| **tfsec / Checkov** | IaC security scanning | CI/CD | Terraform / CloudFormation | CI-time |

### 1.2 Modelo de Cuatro Fases

```
DESIGN-TIME          BUILD-TIME            CI-TIME              RUNTIME
(IDE / Editor)       (Terminal / CLI)      (GitHub Actions)     (EC2 / Docker)

+--------------+     +---------------+     +---------------+   +---------------+
|   Copilot    |     |  Claude Code  |     | 12 Security   |   |  Red Queen    |
|              |---->|               |---->|    Checks     |-->|  (OpenClaw)   |
| Sugerencias  |     | Analisis SAST |     | Secret Scan   |   | Health checks |
| seguras en   |     | Genera fixes  |     | SAST          |   | Scans on-dem  |
| tiempo real  |     | Crea skills   |     | Container     |   | Alertas TG/DC |
|              |     | Review local  |     | IaC / Deps    |   | VPN monitor   |
+--------------+     +---------------+     +---------------+   +---------------+
      |                     |                     |                    |
      v                     v                     v                    v
  Codigo seguro        Codigo auditado      Build verificado    Infra monitoreada
  desde el inicio      antes del push       en cada commit      24/7
```

### 1.3 GitHub Copilot como 4to Agente

Copilot opera en **design-time** — el shift-left mas extremo posible:

**Que aporta:**
- Sugiere codigo seguro mientras escribes (parameterized queries en lugar de f-strings)
- Autocompletado que evita patrones inseguros (no sugiere `pickle.loads` ni `shell=True`)
- Copilot Chat puede explicar por que un patron es vulnerable
- Copilot Workspace para reviews automatizados de PRs antes del merge

**Limitaciones criticas:**
- Copilot **NO tiene acceso a infraestructura** — solo ve codigo
- No puede escanear imagenes Docker, configuraciones de red, ni Terraform en runtime
- No reemplaza scans de dependencias (no conoce CVEs en tiempo real)
- No tiene contexto de la red interna (VPN, mTLS, WireGuard)

**Por que necesitamos Red Queen ademas de Copilot:**

| Capacidad | Copilot | Red Queen |
|---|---|---|
| Sugerir codigo seguro | Si | No |
| Escanear Docker en runtime | No | Si |
| Verificar estado de VPN | No | Si |
| Ejecutar commands on-demand | No | Si |
| Alertas a Telegram/Discord | No | Si |
| Acceso a red interna (10.13.13.0/24) | No | Si |

**Integracion en el taller:**
Copilot es el "4to agente" que opera en design-time. El flujo completo:
1. **Copilot** (design-time) — sugiere codigo seguro al escribir
2. **Claude Code** (build-time) — analiza, audita y genera fixes
3. **GitHub Actions** (CI-time) — 12 checks automaticos en cada commit
4. **Red Queen** (runtime) — monitoreo continuo de infraestructura

---

## 2. Mutual TLS (mTLS) — Implementacion para el Bunker

### 2.1 Por que mTLS

El Bunker ya tiene dos capas de seguridad en la red:

| Capa | Tecnologia | Que protege |
|---|---|---|
| Capa 3 (Red) | WireGuard VPN | Encripta todo el trafico entre nodos, tuneliza sobre UDP |
| Capa 7 (SSH) | Ed25519 keys | Autentica sesiones administrativas |
| **Capa 7 (Aplicacion)** | **mTLS** | **Autentica y encripta comunicacion entre aplicaciones** |

**mTLS agrega valor porque:**

1. **Autenticacion bidireccional** — El servidor valida al cliente Y el cliente valida al servidor. WireGuard autentica nodos, no aplicaciones.
2. **Zero trust a nivel de aplicacion** — Aunque un atacante comprometa la VPN, no puede hablar con OpenClaw sin un certificado valido firmado por nuestra CA.
3. **Auditabilidad** — Nginx loguea el DN del certificado del cliente en cada request, creando un audit trail de quien hizo que.
4. **Revocacion independiente** — Podemos revocar un certificado de cliente sin tocar la VPN ni las SSH keys.

### 2.2 Arquitectura mTLS

```
Parrot OS (10.13.13.2)                    EC2 Agent (10.13.13.4)
+------------------------+                +---------------------------+
|                        |                |                           |
|  curl/app con          |   WireGuard    |  Nginx (mTLS proxy)      |
|  client-cert.pem   ------[UDP:51820]------>  :443                  |
|  client-key.pem        |   Encrypted    |    ssl_verify_client on  |
|                        |   Tunnel       |    |                     |
|  ca-cert.pem           |                |    v                     |
|  (verifica servidor)   |                |  OpenClaw Bot :8080      |
|                        |                |  (solo localhost)        |
+------------------------+                +---------------------------+

Flujo del handshake:
1. Cliente envia ClientHello con TLS 1.3
2. Servidor envia ServerHello + server-cert.pem
3. Cliente verifica server-cert contra ca-cert (confia en nuestra CA)
4. Servidor pide certificado del cliente (ssl_verify_client on)
5. Cliente envia client-cert.pem
6. Servidor verifica client-cert contra ca-cert
7. Handshake completo — canal mutuamente autenticado y encriptado
```

### 2.3 Cadena de Certificados (PKI)

```
Bunker-CA-Root (ca-cert.pem)
|
+-- server-cert.pem (CN=openclaw.bunker.local)
|   SAN: IP:10.13.13.4, IP:127.0.0.1, DNS:openclaw.bunker.local
|   EKU: serverAuth
|   Validez: 365 dias
|
+-- client-cert.pem (CN=parrot-workstation)
    EKU: clientAuth
    Validez: 365 dias
```

**Archivos generados por `scripts/generate_mtls_certs.sh`:**

| Archivo | Proposito | Donde se instala | Quien lo necesita |
|---|---|---|---|
| `ca-cert.pem` | Certificado de la CA Root | Ambos nodos | Servidor y cliente (para verificar al otro) |
| `ca-key.pem` | Llave privada de la CA | **SOLO** maquina de generacion | Solo para firmar nuevos certs |
| `server-cert.pem` | Certificado del servidor | EC2 Agent (Nginx) | Nginx `ssl_certificate` |
| `server-key.pem` | Llave privada del servidor | EC2 Agent (Nginx) | Nginx `ssl_certificate_key` |
| `client-cert.pem` | Certificado del cliente | Parrot OS | curl/app `--cert` |
| `client-key.pem` | Llave privada del cliente | Parrot OS | curl/app `--key` |

### 2.4 Configuracion de Nginx (ya implementada)

El archivo `configs/nginx/nginx-mtls.conf` implementa:

- `ssl_protocols TLSv1.3` — Solo TLS 1.3, sin downgrade posible
- `ssl_verify_client on` — Requiere certificado del cliente
- `ssl_verify_depth 2` — Profundidad de verificacion de la cadena
- Security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options
- `server_tokens off` — Oculta version de Nginx
- Logging con DN del certificado del cliente para audit trail
- Health endpoint sin mTLS (para Docker HEALTHCHECK)

### 2.5 Uso desde el Cliente

```bash
# Test basico — verificar que mTLS funciona
curl --cacert crypto/certs/ca-cert.pem \
     --cert  crypto/certs/client-cert.pem \
     --key   crypto/certs/client-key.pem \
     https://10.13.13.4:8443/health

# Sin certificado — debe devolver 403
curl --cacert crypto/certs/ca-cert.pem \
     https://10.13.13.4:8443/
# Expected: 403 Forbidden

# Con certificado invalido — debe rechazar en handshake
curl --cacert crypto/certs/ca-cert.pem \
     --cert  /tmp/fake-cert.pem \
     --key   /tmp/fake-key.pem \
     https://10.13.13.4:8443/
# Expected: SSL handshake failure
```

### 2.6 Cuando mTLS Agrega Valor vs Cuando es Redundante

| Escenario | Necesita mTLS? | Por que |
|---|---|---|
| Parrot OS -> OpenClaw API | **Si** | Autentica la aplicacion, no solo el nodo |
| SSH entre nodos | No | SSH ya tiene autenticacion fuerte con Ed25519 |
| WireGuard control plane | No | WireGuard usa Curve25519 con llaves pre-compartidas |
| Dashboard (browser) | Opcional | Si el dashboard expone datos sensibles, si |
| GitHub Actions -> AWS | No | Usa IAM roles y OIDC federation |
| Telegram/Discord webhooks | No | Son servicios externos, HTTPS es suficiente |

**Regla general:** mTLS agrega valor cuando hay comunicacion **aplicacion-a-aplicacion** dentro de la red privada y necesitas saber **cual aplicacion** esta conectando, no solo cual **nodo**.

### 2.7 Script de Generacion y Verificacion

El script `scripts/generate_mtls_certs.sh` genera:

1. **CA Root** — RSA 4096 bits, validez 10 anos
2. **Server cert** — RSA 4096, SAN con IPs y DNS del agente, EKU: serverAuth
3. **Client cert** — RSA 4096, EKU: clientAuth
4. **SSH Ed25519 keys** — Para acceso administrativo

El script incluye verificacion automatica:

```bash
# Verificar toda la cadena
openssl verify -CAfile ca-cert.pem server-cert.pem
openssl verify -CAfile ca-cert.pem client-cert.pem

# Ver detalles del certificado
openssl x509 -in server-cert.pem -text -noout | grep -A2 "Subject:\|Issuer:\|Not After\|Subject Alternative"

# Verificar que el par key/cert coincide
diff <(openssl x509 -in server-cert.pem -pubkey -noout) \
     <(openssl rsa -in server-key.pem -pubout 2>/dev/null)
```

**Distribucion segura de certificados:**
```bash
# Desde la maquina de generacion, via WireGuard VPN:
scp -i crypto/keys/bunker_ed25519 \
    crypto/certs/{ca-cert,server-cert,server-key}.pem \
    ubuntu@10.13.13.4:/etc/nginx/certs/

scp -i crypto/keys/bunker_ed25519 \
    crypto/certs/{ca-cert,client-cert,client-key}.pem \
    parrot@10.13.13.2:~/.bunker/certs/
```

---

## 3. Herramientas — Que Tenemos vs Que Falta

### 3.1 Inventario Actual

| Categoria | Herramienta | Version | OWASP | Donde Corre | Estado |
|---|---|---|---|---|---|
| SAST | Bandit | >=1.7.0 | A03:2021 | CI/CD + Local | Implementado |
| SAST | Semgrep | >=1.50.0 | A03:2021 | CI/CD + Local | Implementado |
| Secret Scan | TruffleHog | v3.82.13 | A07:2021 | CI/CD | Implementado |
| Secret Scan | Gitleaks | v2.3.7 | A07:2021 | CI/CD | Implementado |
| SCA | Safety | >=3.0.0 | A06:2021 | CI/CD | Implementado |
| Container | Trivy | 0.28.0 | A06:2021 | CI/CD | Implementado |
| Container | Hadolint | v3.1.0 | A05:2021 | CI/CD | Implementado |
| IaC | tfsec | v1.0.3 | A05:2021 | CI/CD | Implementado |
| IaC | Checkov | v12.2.3 | A05:2021 | CI/CD | Implementado |
| License | pip-licenses | latest | — | CI/CD | Implementado |
| Testing | pytest | >=8.0.0 | A04:2021 | CI/CD + Local | Implementado |
| Alertas | Telegram Bot | — | — | CI/CD | Implementado |
| Alertas | Discord Webhook | — | — | CI/CD | Implementado |
| Crypto | mTLS (TLS 1.3) | — | A02:2021 | Nginx/EC2 | Implementado |
| Crypto | WireGuard | — | A02:2021 | VPN Hub/Peers | Implementado |
| Crypto | Ed25519 SSH | — | A02:2021 | Todos los nodos | Implementado |

### 3.2 Gap Analysis — Que Falta

| Categoria | Falta | Prioridad | Justificacion |
|---|---|---|---|
| DAST | OWASP ZAP / Nuclei | **Alta** | No tenemos testing dinamico — solo estatico |
| Pre-commit | pre-commit hooks | **Alta** | Los secrets pueden llegar al repo antes del CI |
| Runtime | Falco / Sysdig | **Alta** | No detectamos anomalias en runtime |
| SBOM | Syft / CycloneDX | Media | No generamos Software Bill of Materials |
| Secret Scan | detect-secrets | Media | Pre-commit local complementa TruffleHog en CI |
| SCA | Snyk (free tier) | Baja | Safety ya cubre CVEs en Python |
| SAST | SonarQube | Baja | Enterprise — Bandit+Semgrep cubren el scope |
| Container | Docker Scout / Grype | Baja | Trivy ya cubre CVEs en imagenes |
| IaC | Terrascan / KICS | Baja | tfsec+Checkov ya cubren Terraform |

### 3.3 Herramientas de Prioridad Alta — Detalle

#### DAST: OWASP ZAP

**Por que importa:**
SAST encuentra vulnerabilidades en codigo fuente, pero no puede detectar:
- Headers de seguridad faltantes en respuestas HTTP reales
- Configuraciones de CORS incorrectas
- Vulnerabilidades que solo aparecen con la app corriendo (race conditions, session management)
- Problemas de autenticacion/autorizacion en flujos reales

**Como se integraria:**

```yaml
# En el pipeline, despues de levantar la app:
dast:
  name: "DAST — OWASP ZAP"
  runs-on: ubuntu-latest
  services:
    app:
      image: ${{ env.DOCKER_IMAGE }}:${{ env.DOCKER_TAG }}
      ports: ["5000:5000"]
  steps:
    - uses: zaproxy/action-baseline@v0.12.0
      with:
        target: "http://localhost:5000"
        rules_file_name: ".zap/rules.tsv"
        allow_issue_writing: false
```

**Timeline:** v2 del pipeline.

#### Pre-commit Hooks

**Por que importa:**
Sin pre-commit hooks, un desarrollador puede hacer `git commit` con un API key hardcodeado. El CI/CD lo detecta *despues* de que el secret ya esta en el historial de git. Con pre-commit, el secret se bloquea *antes* de entrar al repo.

**Como se integraria:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-ll', '-q']
```

```bash
# Instalacion para el equipo:
pip install pre-commit
pre-commit install
# A partir de aqui, cada git commit ejecuta los hooks automaticamente
```

**Timeline:** Implementar en la siguiente sesion del taller.

#### Runtime Security: Falco

**Por que importa:**
Ninguna de las herramientas actuales detecta anomalias en runtime:
- Un proceso inesperado ejecutandose dentro de un container
- Una shell interactiva abierta en un container de produccion
- Trafico de red inusual desde un container
- Acceso a archivos sensibles (/etc/shadow, /proc)

**Como se integraria:**

```yaml
# docker-compose.yml adicional
falco:
  image: falcosecurity/falco:0.37.1
  privileged: true
  volumes:
    - /var/run/docker.sock:/host/var/run/docker.sock:ro
    - /proc:/host/proc:ro
    - ./configs/falco/rules.yaml:/etc/falco/rules.d/bunker.yaml:ro
  command: ["/usr/bin/falco", "-o", "json_output=true"]
```

Reglas custom para el Bunker:
```yaml
# configs/falco/rules.yaml
- rule: Shell in OpenClaw Container
  desc: Detectar shell interactiva en el container de OpenClaw
  condition: >
    spawned_process and container.name = "openclaw-bunker"
    and proc.name in (bash, sh, zsh)
  output: "Shell detectada en OpenClaw (user=%user.name command=%proc.cmdline)"
  priority: WARNING
```

**Timeline:** Requiere acceso root al host — implementar en produccion, no en el taller.

---

## 4. Meta-Seguridad — Asegurando el Pipeline Mismo

### 4.1 Modelo de Amenazas del Pipeline

Un atacante que comprometa el pipeline CI/CD puede:
- Inyectar malware en los artefactos de build
- Exfiltrar secrets del repositorio
- Deshabilitar checks de seguridad para colar vulnerabilidades
- Enviar notificaciones falsas a Telegram/Discord

Asi protegemos cada vector:

### 4.2 GitHub Secrets — Cifrado con libsodium

Los secrets del repositorio (tokens, webhook URLs) estan cifrados:

- GitHub usa **libsodium sealed boxes** (Curve25519 + XSalsa20-Poly1305)
- Los secrets **nunca** aparecen en logs — GitHub los redacta automaticamente
- Los secrets **no son accesibles** desde PRs de forks (proteccion contra pull_request_target attacks)
- Rotacion recomendada: cada 90 dias para tokens, cada 30 dias para passwords

**Secrets configurados:**

| Secret | Proposito | Scope |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Notificaciones a Telegram | Actions |
| `TELEGRAM_CHAT_ID` | Canal de Telegram destino | Actions |
| `DISCORD_WEBHOOK_URL` | Notificaciones a Discord | Actions |

**No almacenamos en GitHub Secrets:**
- AWS credentials (usar OIDC federation en produccion)
- Llaves privadas de mTLS/SSH (se generan localmente, se transfieren via VPN)
- Anthropic API keys (se almacenan en el nodo EC2 via environment variables del sistema)

### 4.3 GITHUB_TOKEN — Permisos Minimos

El `GITHUB_TOKEN` automatico de GitHub Actions se usa con permisos reducidos:

```yaml
# El pipeline NO declara permissions: write-all
# Solo los permisos que realmente necesita:
# - contents: read (checkout del codigo)
# - security-events: write (upload SARIF si se habilita)
# El token expira automaticamente al finalizar el job
```

**Permisos que NO necesitamos y NO solicitamos:**
- `packages: write` — No publicamos paquetes
- `deployments: write` — No hacemos deploy desde CI
- `issues: write` — No creamos issues automaticamente
- `pull-requests: write` — No comentamos PRs programaticamente

### 4.4 Actions Pinneadas por SHA

Todas las GitHub Actions de terceros estan pinneadas por version **exacta**, no por tag mutable:

```yaml
# CORRECTO — version fija, no puede ser reescrita
uses: actions/checkout@v4
uses: trufflesecurity/trufflehog@v3.82.13
uses: gitleaks/gitleaks-action@v2.3.7
uses: aquasecurity/trivy-action@0.28.0
uses: hadolint/hadolint-action@v3.1.0
uses: aquasecurity/tfsec-action@v1.0.3
uses: bridgecrewio/checkov-action@v12.2.3

# INCORRECTO — tag mutable, un atacante podria reescribirlo
uses: actions/checkout@main        # NUNCA
uses: some-action@latest           # NUNCA
```

**Por que es critico:**
Un ataque de supply chain (como el incidente de `codecov/bash-uploader` en 2021) puede modificar una action referenciada por `@main`. Al pinnear por version, el hash del commit es inmutable.

**Para maxima seguridad en produccion**, pinnear por SHA completo:
```yaml
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 4.5 CODEOWNERS — Proteger Workflows

El archivo `CODEOWNERS` protege archivos criticos requiriendo review explicito:

```
# Propuesto para implementar:
# .github/CODEOWNERS

# El pipeline CI/CD requiere review del lead de seguridad
.github/workflows/    @Jawy77
.github/              @Jawy77

# Los configs de infra requieren review
configs/              @Jawy77
terraform/            @Jawy77

# El Dockerfile hardened requiere review
docker/openclaw/      @Jawy77
```

Con CODEOWNERS + branch protection, nadie puede modificar el pipeline sin aprobacion.

### 4.6 Branch Protection Rules

Reglas recomendadas para el branch `main`:

| Regla | Estado | Proposito |
|---|---|---|
| Require PR before merge | Recomendado | Impedir push directo a main |
| Require status checks | Recomendado | El pipeline debe pasar antes del merge |
| Require review (1+) | Recomendado | Al menos 1 reviewer humano |
| Dismiss stale reviews | Recomendado | Si el PR cambia, el review anterior se invalida |
| Require signed commits | Opcional | Verificar identidad del committer con GPG |
| Restrict force pushes | Recomendado | Proteger historial contra reescritura |
| Require linear history | Opcional | Evitar merge commits, facilitar auditorias |

**Nota:** Para el taller, usamos push directo para agilidad. En produccion, activar todas las reglas.

### 4.7 Signed Commits (GPG)

Verificar la identidad del committer es el ultimo eslabón de la cadena de confianza:

```bash
# Generar key GPG
gpg --full-generate-key  # Elegir RSA 4096, email del committer

# Exportar la key publica
gpg --armor --export jawy.romero@gmail.com

# Configurar git para firmar automaticamente
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true

# Subir la key publica a GitHub:
# Settings -> SSH and GPG keys -> New GPG key
```

Con signed commits + branch protection, la cadena de confianza es:
```
GPG verifica identidad del autor
    -> CODEOWNERS requiere reviewer autorizado
        -> Branch protection requiere checks pasados
            -> Pipeline ejecuta 12 checks automaticos
                -> Merge solo si todo pasa
```

### 4.8 Checklist de Meta-Seguridad

| Control | Implementado | Pendiente |
|---|---|---|
| Secrets cifrados con libsodium | Si | — |
| GITHUB_TOKEN permisos minimos | Si | — |
| Actions pinneadas por version | Si | Migrar a SHA completo |
| Step summaries (audit trail) | Si | — |
| Artifacts con retencion 30 dias | Si | — |
| continue-on-error (no bloquea pipeline) | Si | — |
| Notificaciones a Telegram/Discord | Si | — |
| CODEOWNERS | No | Alta |
| Branch protection rules | No | Alta |
| Signed commits (GPG) | No | Media |
| Dependabot para actions | No | Media |
| Secret scanning (GitHub native) | No | Activar en Settings |
| OIDC para AWS (no static keys) | No | Alta para produccion |

---

## 5. Modelo de Defensa en Profundidad

```
+====================================================================+
|                     INTERNET / ATACANTES                            |
+====================================================================+
           |                                          |
           v                                          v
+-----------------------+                 +-----------------------+
|   CAPA 1: RED         |                 |   CAPA 1: CI/CD       |
|   WireGuard VPN       |                 |   GitHub Actions      |
|   Curve25519 + ChaCha |                 |   12 Security Checks  |
|   Split tunneling     |                 |   Secrets cifrados    |
|   10.13.13.0/24       |                 |   Actions pinneadas   |
+-----------+-----------+                 +-----------+-----------+
            |                                         |
            v                                         v
+-----------------------+                 +-----------------------+
|   CAPA 2: TRANSPORTE  |                 |   CAPA 2: CODIGO      |
|   mTLS (TLS 1.3)      |                 |   SAST (Bandit+Semgrep|
|   Nginx reverse proxy  |                 |   Secret scanning     |
|   CA propia            |                 |   Dependency audit    |
|   Client certs         |                 |   License compliance  |
+-----------+-----------+                 +-----------+-----------+
            |                                         |
            v                                         v
+-----------------------+                 +-----------------------+
|   CAPA 3: APLICACION  |                 |   CAPA 3: INFRA       |
|   Docker hardened      |                 |   IaC scanning        |
|   Non-root user        |                 |   Container CVEs      |
|   cap_drop: ALL        |                 |   Dockerfile lint     |
|   Read-only filesystem |                 |   Zero-trust SGs      |
+-----------+-----------+                 +-----------+-----------+
            |                                         |
            v                                         v
+-----------------------+                 +-----------------------+
|   CAPA 4: HOST        |                 |   CAPA 4: ALERTAS     |
|   SSH Ed25519 only     |                 |   Telegram real-time  |
|   Firewall (iptables)  |                 |   Discord embeds      |
|   IMDSv2 obligatorio   |                 |   Dashboard Mantishield|
|   EBS encriptado       |                 |   Activity log        |
+-----------------------+                 +-----------------------+
```

---

## 6. Resumen Ejecutivo para el CISO

**Postura actual:** El Bunker DevSecOps implementa 12 checks de seguridad automaticos que cubren 7 de las 10 categorias del OWASP Top 10 2021, ejecutandose en menos de 10 minutos y con costo $0 en herramientas open-source.

**Fortalezas:**
- Pipeline CI/CD completamente automatizado con 12 checks en paralelo
- Cobertura de SAST, SCA, secret scanning, container security, e IaC security
- Red privada con WireGuard VPN + mTLS para comunicacion de aplicaciones
- Docker hardening con CIS Benchmark compliance
- Terraform con zero-trust security groups (SSH solo via VPN)
- Notificaciones en tiempo real a Telegram y Discord
- Dashboard conversacional para consulta de estado de seguridad

**Gaps identificados (roadmap):**
1. **DAST** — No hay testing dinamico. Prioridad alta para v2.
2. **Pre-commit hooks** — Secrets pueden llegar al repo antes del CI. Prioridad alta.
3. **Runtime security** — No hay deteccion de anomalias en containers. Prioridad alta para produccion.
4. **SBOM** — No generamos Software Bill of Materials. Prioridad media.
5. **Branch protection** — Push directo a main habilitado para el taller. Prioridad alta para produccion.

**Costo total de herramientas:** $0 (100% open-source)
**Tiempo de pipeline:** < 10 minutos (6 jobs en paralelo)
**Cobertura OWASP:** A01, A02, A03, A04, A05, A06, A07 (7/10)

---

*Documento generado para el Bunker DevSecOps Workshop — Mantishield / Comunidad Claude Anthropic Colombia*
