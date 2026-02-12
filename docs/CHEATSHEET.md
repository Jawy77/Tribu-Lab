# =============================================================================
# 📋 CHEATSHEET — Comandos para la Demo en Vivo
# Búnker DevSecOps Workshop — Comunidad Claude Anthropic Colombia
# =============================================================================
# Tener esta hoja abierta durante el taller para copiar/pegar rápido.
# =============================================================================


# ══════════════════════════════════════════════════════════════
# MÓDULO 1: WireGuard & La Trinidad
# ══════════════════════════════════════════════════════════════

# Verificar estado de WireGuard
sudo wg show

# Ping a todos los nodos
ping -c 1 10.13.13.1 && echo "Hub OK" || echo "Hub DOWN"
ping -c 1 10.13.13.2 && echo "Parrot OK" || echo "Parrot DOWN"
ping -c 1 10.13.13.4 && echo "Agent OK" || echo "Agent DOWN"

# Ver rutas (demostrar split tunneling)
ip route show

# Verificar que SSH NO está abierto al mundo
ss -tlnp | grep :22

# Health check completo
./scripts/verify_bunker.sh


# ══════════════════════════════════════════════════════════════
# MÓDULO 2: Pipeline DevSecOps (Security Scanning)
# ══════════════════════════════════════════════════════════════

# Ejecutar Bandit (Python SAST) — mostrará las vulns de la app
bandit -r vulnerable_app/ -ll

# Ejecutar Semgrep (multi-lenguaje)
semgrep --config auto vulnerable_app/

# Safety — revisar dependencias
safety check -r vulnerable_app/requirements.txt

# Script todo-en-uno
./scripts/run_security_checks.sh

# Claude Code — review inteligente (¡la estrella del show!)
claude -p "Analiza vulnerable_app/app.py. Identifica cada vulnerabilidad de seguridad, clasifícala por severidad (CRITICAL/HIGH/MEDIUM/LOW), explica el impacto, y muestra el código corregido."

# Claude Code — generar fix automático
claude -p "Lee vulnerable_app/app.py y genera una versión completamente segura del archivo. Corrige SQL injection, command injection, hardcoded secrets, y todas las demás vulnerabilidades. Mantén la misma funcionalidad."


# ══════════════════════════════════════════════════════════════
# MÓDULO 2: Skills para Claude Code & Marketplace
# ══════════════════════════════════════════════════════════════

# Ver la estructura del skill que creamos
tree skills/devsecops-pipeline/

# Leer el SKILL.md (el corazón del skill)
cat skills/devsecops-pipeline/SKILL.md | head -20

# Validar que el skill cumple con las reglas del marketplace
cd skills && python quick_validate.py devsecops-pipeline/

# Empaquetar el skill como .skill (ZIP con estructura)
python package_skill.py devsecops-pipeline/ ../dist/

# Ver qué contiene el .skill empaquetado
unzip -l ../dist/devsecops-pipeline.skill

# Instalar el skill en Claude Code (los asistentes pueden hacer esto)
# claude install-skill dist/devsecops-pipeline.skill

# Demo: Pedirle a Claude Code que USE el skill
claude -p "Crea un pipeline de seguridad para una app Python con Flask"

# Demo: Pedirle a Claude Code que CREE un skill nuevo desde cero
claude "Crea un skill para auditar Dockerfiles basado en CIS Benchmark. 
Incluye 3 eval cases."

# Demo: Auditar un skill existente
claude -p "Audita el skill en skills/devsecops-pipeline/. Verifica 
estructura, calidad de instrucciones, cobertura de evals, y seguridad."

# Ver la guía completa de cómo crear skills
cat docs/GUIDE-CREATING-SKILLS.md


# ══════════════════════════════════════════════════════════════
# MÓDULO 3: Docker Hardening & OpenClaw (El Búnker)
# ══════════════════════════════════════════════════════════════

# Construir las imágenes
docker compose build

# Levantar el stack
docker compose up -d

# Verificar que el container corre como non-root
docker exec openclaw-bunker whoami
docker exec openclaw-bunker id

# Verificar capabilities droppeadas
docker inspect openclaw-bunker | jq '.[0].HostConfig.CapDrop'
docker inspect openclaw-bunker | jq '.[0].HostConfig.CapAdd'

# Verificar read-only filesystem
docker exec openclaw-bunker touch /test_write 2>&1 || echo "✓ Filesystem is read-only"

# Verificar que no puede escalar privilegios
docker inspect openclaw-bunker | jq '.[0].HostConfig.SecurityOpt'

# Escanear la imagen con Trivy
trivy image openclaw-bunker:latest --severity HIGH,CRITICAL

# Lint del Dockerfile
hadolint docker/openclaw/Dockerfile

# Ver logs
docker compose logs -f openclaw


# ══════════════════════════════════════════════════════════════
# MÓDULO 4: Criptografía Aplicada
# ══════════════════════════════════════════════════════════════

# Generar toda la PKI (CA + server + client certs)
chmod +x scripts/generate_mtls_certs.sh
./scripts/generate_mtls_certs.sh

# Verificar la cadena de certificados
openssl verify -CAfile crypto/certs/ca-cert.pem crypto/certs/server-cert.pem
openssl verify -CAfile crypto/certs/ca-cert.pem crypto/certs/client-cert.pem

# Inspeccionar el certificado del servidor
openssl x509 -in crypto/certs/server-cert.pem -text -noout | head -30

# Ver las SANs (Subject Alternative Names)
openssl x509 -in crypto/certs/server-cert.pem -text -noout | grep -A 2 "Subject Alternative"

# Test de conexión mTLS (cuando Nginx está corriendo)
curl -v \
    --cert crypto/certs/client-cert.pem \
    --key crypto/certs/client-key.pem \
    --cacert crypto/certs/ca-cert.pem \
    https://10.13.13.4:8443/health

# Test SIN certificado (debe fallar con 403)
curl -v -k https://10.13.13.4:8443/ 2>&1 | grep "400\|403\|SSL"

# SSH con Ed25519 (al agente desde Parrot via VPN)
ssh -i crypto/keys/bunker_ed25519 ubuntu@10.13.13.4

# Ver fingerprint de la llave
ssh-keygen -l -f crypto/keys/bunker_ed25519.pub


# ══════════════════════════════════════════════════════════════
# MÓDULO 5: Terraform & IaC Security
# ══════════════════════════════════════════════════════════════

# Escanear Terraform con tfsec
tfsec terraform/

# Checkov scan
checkov -d terraform/

# Terraform plan (si hay credenciales AWS configuradas)
# cd terraform && terraform init && terraform plan


# ══════════════════════════════════════════════════════════════
# MÓDULO 6: Tests de Seguridad Automatizados
# ══════════════════════════════════════════════════════════════

# Ejecutar todos los tests
pytest tests/ -v

# Solo tests de Docker
pytest tests/test_security.py::TestDockerSecurity -v

# Solo tests de crypto
pytest tests/test_security.py::TestCryptoConfig -v


# ══════════════════════════════════════════════════════════════
# COMANDOS DE EMERGENCIA (por si algo falla en la demo 😅)
# ══════════════════════════════════════════════════════════════

# Reiniciar WireGuard
sudo wg-quick down wg0 && sudo wg-quick up wg0

# Reiniciar todos los containers
docker compose down && docker compose up -d

# Ver logs de error
docker compose logs --tail=50

# Verificar que Docker daemon está corriendo
systemctl status docker

# Liberar espacio si se llena el disco
docker system prune -f
