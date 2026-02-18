# Workshop Guide — Bunker DevSecOps

> Guia paso a paso para los asistentes del taller.
> Abre esto en tu laptop y sigue cada parte mientras el facilitador presenta.

**Facilitador:** Jawy Romero (@hackwy) — Mantishield
**Comunidad:** Tribu | Hacklab Bogota | Ethereum Bogota
**Duracion:** 2 horas
**Nivel:** Intermedio (saber usar terminal + git basico)

---

## PARTE 1 — Setup (5 min)

> Haz esto mientras arranca el taller. Si ya tienes Python 3.10+, deberia funcionar.

```bash
# Clonar el repositorio
git clone https://github.com/Jawy77/Tribu-Lab.git
cd Tribu-Lab

# Instalar dependencias del proyecto
pip install -r requirements.txt

# Instalar herramientas de seguridad
pip install bandit semgrep pytest safety

# Verificar que todo quedo instalado
bandit --version
semgrep --version
pytest --version
```

> **TIP:** Si tienes error de "externally-managed-environment" en Debian/Ubuntu:
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -r requirements.txt bandit semgrep pytest safety
> ```

**Verificacion rapida:**
```bash
# Si esto funciona, estas listo
bandit -r vulnerable_app/ -ll --quiet
# Debe mostrar ~7 issues
```

---

## PARTE 2 — Descubre las Vulnerabilidades (10 min)

> Vamos a analizar una app Flask con 7 vulnerabilidades plantadas.

### 2.1 — Lee el codigo vulnerable

```bash
cat vulnerable_app/app.py
```

Busca estas 7 vulnerabilidades mientras lees:

| # | Vulnerabilidad | Linea | Pista |
|---|---|---|---|
| 1 | Hardcoded secrets | 27-29 | `SECRET_KEY = "..."` |
| 2 | SQL Injection | 40 | `f"SELECT * FROM..."` |
| 3 | Command Injection | 54 | `shell=True` |
| 4 | Insecure Deserialization | 70 | `pickle.loads(data)` |
| 5 | Path Traversal | 80 | `open(f"/app/data/{filename}")` |
| 6 | SSRF | 93 | `urlopen(url)` sin validacion |
| 7 | Debug Mode | 134 | `debug=True` en produccion |

### 2.2 — Ejecuta Bandit (SAST para Python)

```bash
bandit -r vulnerable_app/ -ll
```

**Preguntas para pensar:**
- Cuantos issues encontro Bandit? Deberian ser 7+
- Puedes identificar la SQL injection en la linea 40?
- Por que `pickle.loads` es peligroso? (Pista: permite Remote Code Execution)
- Que pasa si un usuario envia `host=; rm -rf /` al endpoint `/ping`?

### 2.3 — Ejecuta Semgrep (SAST multi-lenguaje)

```bash
semgrep --config auto vulnerable_app/ --quiet
```

Semgrep encuentra patterns que Bandit no detecta (SSRF, path traversal con mas contexto).

---

## PARTE 3 — Compara con la Version Segura (10 min)

> Ahora veamos COMO se corrigen estas vulnerabilidades.

### 3.1 — Diff lado a lado

```bash
diff vulnerable_app/app.py vulnerable_app/app_secure.py
```

Correcciones principales:

| Vulnerabilidad | Antes (inseguro) | Despues (seguro) |
|---|---|---|
| Hardcoded secrets | `SECRET_KEY = "super_secret"` | `os.environ.get("SECRET_KEY")` |
| SQL Injection | `f"SELECT ... '{username}'"` | `cursor.execute("...?", (username,))` |
| Command Injection | `shell=True` con f-string | Lista de args + regex validation |
| Pickle | `pickle.loads(data)` | `request.get_json()` |
| Path Traversal | `open(f"/app/{file}")` | `Path.resolve()` + base dir check |
| SSRF | `urlopen(url)` directo | Allowlist de dominios + scheme check |
| Debug Mode | `debug=True` hardcoded | `os.environ.get("FLASK_DEBUG")` |

### 3.2 — Verifica con Bandit

```bash
bandit -r vulnerable_app/app_secure.py -ll
```

**Resultado esperado:** 0 issues de severidad Medium o superior.

**Pregunta:** La version segura tiene 0 findings, pero eso significa que es 100% segura? (No — SAST no detecta problemas de logica de negocio, autorizacion, o race conditions.)

---

## PARTE 4 — Ejecuta los Tests de Seguridad (5 min)

> 22 tests automatizados que verifican la postura de seguridad del proyecto.

```bash
pytest tests/ -v
```

Los tests estan organizados por OWASP Top 10:

| Grupo | OWASP | Que verifica |
|---|---|---|
| TestSecrets | A07:2021 | No hay passwords ni API keys en codigo |
| TestInjection | A03:2021 | No hay SQL injection ni shell=True en produccion |
| TestSecurityConfig | A05:2021 | Dockerfiles seguros, Terraform sin 0.0.0.0/0 |
| TestCryptoTransport | A02:2021 | WireGuard con Curve25519, SSH con Ed25519 |
| TestVulnerableAppDetection | — | La app demo SI tiene las vulns (intencional) |
| TestDependencies | A06:2021 | requirements.txt existe y es auditable |

**Pregunta:** Por que el test `test_vulnerable_app_has_sqli` PASA? (Porque verifica que la app vulnerable SI tiene SQL injection — es material de demo.)

```bash
# Ejecutar solo un grupo especifico:
pytest tests/ -v -m owasp_a03   # Solo injection tests
pytest tests/ -v -m owasp_a07   # Solo secrets tests
```

---

## PARTE 5 — Fork + Tu Propio Pipeline (10 min)

> Haz fork del repo y mira como corren los 12 checks en TU cuenta.

### 5.1 — Fork el repositorio

1. Ve a [github.com/Jawy77/Tribu-Lab](https://github.com/Jawy77/Tribu-Lab)
2. Click en **Fork** (esquina superior derecha)
3. Espera a que se cree la copia en tu cuenta

### 5.2 — Configura secrets (opcional, para alertas)

1. Ve a tu fork: `github.com/<tu-user>/Tribu-Lab`
2. **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret** para cada uno:

| Secret | Como obtenerlo |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Hablar con @BotFather en Telegram |
| `TELEGRAM_CHAT_ID` | Crear grupo, agregar bot, ver getUpdates |
| `DISCORD_WEBHOOK_URL` | Canal > Integraciones > Nuevo Webhook |

> **TIP:** Los secrets son opcionales. Sin ellos el pipeline funciona igual, pero no envia alertas.

### 5.3 — Triggerea el pipeline

```bash
# Clona TU fork
git clone https://github.com/<tu-user>/Tribu-Lab.git
cd Tribu-Lab

# Haz cualquier cambio
echo "# Mi taller DevSecOps" >> README.md

# Push
git add README.md
git commit -m "test: trigger pipeline"
git push
```

### 5.4 — Mira los resultados

1. Ve a **Actions** en tu fork
2. Veras los 6 jobs corriendo en paralelo
3. Click en cada job para ver los findings
4. Si configuraste secrets, revisa Telegram/Discord

```
[Job 1] Secret Scanning    — TruffleHog + Gitleaks
[Job 2] SAST + Dependencies — Bandit + Semgrep + Safety
[Job 3] Container Security  — Trivy + Hadolint
[Job 4] IaC Security        — tfsec + Checkov
[Job 5] License Audit       — pip-licenses
[Job 6] Security Tests      — pytest (22 tests)
   |
   +---> [Job 7] Notify — Telegram + Discord
```

---

## PARTE 6 — Challenges (el resto del taller)

> Retos para los que quieran ir mas alla. Cada uno vale puntos de cred en la comunidad.

### Challenge 1 — Pre-commit Hooks

Configura pre-commit para que detecte secrets ANTES del commit:

```bash
pip install pre-commit

# Crear .pre-commit-config.yaml con:
# - detect-private-key
# - detect-secrets
# - bandit

pre-commit install
# Ahora intenta commitear un secret...
echo 'API_KEY = "sk-real-key-12345"' >> test.py
git add test.py
git commit -m "test"
# Deberia BLOQUEARSE
```

### Challenge 2 — Crea Tu Propio Skill para Claude Code

```bash
# Mira el ejemplo existente
cat skills/devsecops-pipeline/SKILL.md

# Crea tu skill
mkdir -p skills/mi-skill
# Edita skills/mi-skill/SKILL.md con frontmatter YAML
# Valida: python3 skills/quick_validate.py skills/mi-skill/
# Empaqueta: python3 skills/package_skill.py skills/mi-skill/
```

### Challenge 3 — DAST con OWASP ZAP

```bash
# Instalar ZAP
docker pull zaproxy/zap-stable

# Levantar la app vulnerable
docker build -t demo-app -f docker/app/Dockerfile .
docker run -d -p 5000:5000 demo-app

# Ejecutar ZAP baseline scan
docker run --rm --net=host zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:5000
```

### Challenge 4 — Dockerfile Hardened

Analiza `docker/openclaw/Dockerfile` y responde:
- Que hace `cap_drop: ALL`?
- Por que usa multi-stage build?
- Que pasa sin `USER openclaw`?
- Para que sirve `tini` como ENTRYPOINT?

### Challenge 5 — Conecta Alertas a Tu Telegram

```bash
# 1. Habla con @BotFather -> /newbot
# 2. Crea un grupo y agrega tu bot
# 3. Envia un mensaje al grupo
# 4. Ve a: https://api.telegram.org/bot<TOKEN>/getUpdates
# 5. Busca "chat":{"id":-100XXXXXXXXXX}
# 6. Agrega los secrets en tu fork de GitHub
# 7. Haz push y espera la alerta!
```

---

## PARTE 7 — Demo en Vivo: Red Queen desde Telegram

> Yo (Jawy) voy a ejecutar esto en vivo. Solo observen.

**Lo que van a ver:**

1. Desde mi telefono, envio un comando a Red Queen (OpenClaw bot) via Telegram
2. El bot en Virginia (EC2, 10.13.13.4) recibe el comando por VPN cifrada (WireGuard)
3. Red Queen ejecuta los security checks en el servidor remoto
4. Los resultados viajan de vuelta por la VPN a mi laptop en Bogota
5. Las alertas llegan a Telegram y Discord en tiempo real
6. El dashboard (Mantishield) se actualiza automaticamente

```
Bogota (Parrot OS)              Virginia (EC2 Agent)
+------------------+            +------------------+
|                  | WireGuard  |                  |
|  Jawy @ laptop  |<---------->|  Red Queen       |
|  10.13.13.2     | Encrypted  |  10.13.13.4      |
|                  | UDP:51820  |  Docker + Trivy   |
+------------------+            +------------------+
        |                               |
        |    Telegram Bot API           |
        +<--------- Alertas -----------+
        |
        v
  Dashboard Mantishield
  (localhost:8080)
```

**Comunicacion asegurada con:**
- WireGuard VPN (Curve25519 + ChaCha20-Poly1305) — capa de red
- mTLS (TLS 1.3 + CA propia) — capa de aplicacion
- SSH Ed25519 — acceso administrativo

---

## Links y Recursos

### QR Codes

```
+------------------+  +------------------+  +------------------+
|                  |  |                  |  |                  |
|  [QR REPO]       |  |  [QR DISCORD]    |  |  [QR TELEGRAM]   |
|                  |  |                  |  |                  |
|  github.com/     |  |  discord.gg/     |  |  t.me/           |
|  Jawy77/         |  |  bunker-devsecops|  |  claude_co       |
|  Tribu-Lab       |  |                  |  |                  |
+------------------+  +------------------+  +------------------+
     Repositorio          Discord              Telegram
```

> **TIP:** Toma foto de estos QR codes ahora. Los vas a necesitar.

### Herramientas mencionadas en el taller

| Herramienta | Para que sirve | Link |
|---|---|---|
| Bandit | SAST para Python | https://bandit.readthedocs.io |
| Semgrep | SAST multi-lenguaje | https://semgrep.dev |
| TruffleHog | Secret scanning git history | https://trufflesecurity.com |
| Gitleaks | Secret scanning code | https://gitleaks.io |
| Trivy | Container CVE scanning | https://trivy.dev |
| Hadolint | Dockerfile linting | https://github.com/hadolint/hadolint |
| tfsec | Terraform security | https://aquasecurity.github.io/tfsec |
| Checkov | IaC policy compliance | https://www.checkov.io |
| Safety | Python dependency audit | https://safetycli.com |
| OWASP ZAP | DAST (testing dinamico) | https://www.zaproxy.org |
| Claude Code | AI copilot para seguridad | https://claude.ai/claude-code |
| WireGuard | VPN moderna | https://www.wireguard.com |

### Documentacion del proyecto

| Documento | Contenido |
|---|---|
| `README.md` | Overview del proyecto + Quick Start |
| `docs/SECURITY-STACK.md` | Stack completo de seguridad + mTLS |
| `docs/BRANCHING-STRATEGY.md` | Estrategia de branches y ambientes |
| `docs/CHEATSHEET.md` | Comandos rapidos de referencia |
| `docs/WORKSHOP-GUIDE.md` | Esta guia |

---

## Checklist Final

Antes de irte, verifica que completaste:

- [ ] Clone del repo funcionando
- [ ] Bandit ejecuta sin errores
- [ ] Encontraste las 7 vulnerabilidades en app.py
- [ ] Entiendes la diferencia entre app.py y app_secure.py
- [ ] Los 22 tests pasan con pytest
- [ ] (Opcional) Fork con pipeline corriendo
- [ ] (Opcional) Alertas llegando a tu Telegram
- [ ] (Bonus) Completaste al menos 1 challenge

---

> **Gracias por asistir!**
> Este repositorio queda publico — pueden seguir practicando.
> Unanse a la comunidad en Discord y Telegram para dudas.
>
> *Hecho con seguridad por @hackwy para la comunidad*
> *Mantishield | Tribu | Hacklab Bogota | Ethereum Bogota*

---

*Bunker DevSecOps Workshop — 12 Checks | OWASP Top 10 | $0 cost | < 10 min*
