#!/usr/bin/env bash
# =============================================================================
# 🔍 Security Checks Runner — Búnker DevSecOps
# Ejecuta todas las herramientas de seguridad localmente
# Ideal para demo en vivo durante el taller
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_DIR="./reports"
mkdir -p "$REPORT_DIR"

header() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
fail()    { echo -e "${RED}[✗]${NC} $1"; }

TOTAL_ISSUES=0

# ── 1. Bandit — Python SAST ──────────────────────────────────
header "🐍 BANDIT — Python Security Linter"

if command -v bandit &> /dev/null; then
    echo "Escaneando vulnerable_app/..."
    bandit -r vulnerable_app/ -f screen -ll 2>/dev/null || true
    bandit -r vulnerable_app/ -f json -o "$REPORT_DIR/bandit.json" 2>/dev/null || true

    BANDIT_ISSUES=$(bandit -r vulnerable_app/ -f json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('results', [])))
" 2>/dev/null || echo "0")

    TOTAL_ISSUES=$((TOTAL_ISSUES + BANDIT_ISSUES))
    warning "Bandit encontró $BANDIT_ISSUES issues"
else
    fail "Bandit no instalado. Instalar: pip install bandit"
fi

# ── 2. Semgrep — Multi-language SAST ─────────────────────────
header "🔎 SEMGREP — Multi-language Scanner"

if command -v semgrep &> /dev/null; then
    semgrep --config auto vulnerable_app/ --json -o "$REPORT_DIR/semgrep.json" 2>/dev/null || true
    semgrep --config auto vulnerable_app/ 2>/dev/null || true
else
    fail "Semgrep no instalado. Instalar: pip install semgrep"
fi

# ── 3. Safety — Dependency Check ─────────────────────────────
header "📦 SAFETY — Dependency Vulnerabilities"

if command -v safety &> /dev/null; then
    if [ -f "vulnerable_app/requirements.txt" ]; then
        safety check -r vulnerable_app/requirements.txt 2>/dev/null || true
    fi
else
    fail "Safety no instalado. Instalar: pip install safety"
fi

# ── 4. Trivy — Container Scan ────────────────────────────────
header "🐳 TRIVY — Container Vulnerability Scan"

if command -v trivy &> /dev/null; then
    if docker image inspect demo-app:latest &>/dev/null; then
        trivy image --severity HIGH,CRITICAL demo-app:latest 2>/dev/null || true
    else
        warning "Imagen demo-app no encontrada. Ejecutar: docker compose build demo-app"
    fi
else
    warning "Trivy no instalado. Ver: https://aquasecurity.github.io/trivy/"
fi

# ── 5. Hadolint — Dockerfile Linter ─────────────────────────
header "📋 HADOLINT — Dockerfile Best Practices"

if command -v hadolint &> /dev/null; then
    echo "Escaneando docker/openclaw/Dockerfile..."
    hadolint docker/openclaw/Dockerfile || true
    echo ""
    echo "Escaneando docker/app/Dockerfile..."
    hadolint docker/app/Dockerfile || true
else
    warning "Hadolint no instalado. Ver: https://github.com/hadolint/hadolint"
fi

# ── 6. tfsec — Terraform Security ───────────────────────────
header "🏗️ TFSEC — Terraform Security Scanner"

if command -v tfsec &> /dev/null; then
    tfsec terraform/ 2>/dev/null || true
else
    warning "tfsec no instalado. Ver: https://aquasecurity.github.io/tfsec/"
fi

# ── 7. Git Secrets Check ────────────────────────────────────
header "🔑 SECRET DETECTION — Buscando secrets en el código"

echo "Buscando patrones de secrets..."
SECRETS_FOUND=0

# Buscar patrones comunes de secrets
grep -rn "password\s*=\s*['\"]" vulnerable_app/ && SECRETS_FOUND=$((SECRETS_FOUND+1)) || true
grep -rn "api_key\s*=\s*['\"]" vulnerable_app/ && SECRETS_FOUND=$((SECRETS_FOUND+1)) || true
grep -rn "secret.*=.*['\"]" vulnerable_app/ && SECRETS_FOUND=$((SECRETS_FOUND+1)) || true
grep -rn "sk-ant-" vulnerable_app/ && SECRETS_FOUND=$((SECRETS_FOUND+1)) || true

if [ $SECRETS_FOUND -gt 0 ]; then
    fail "Se encontraron $SECRETS_FOUND patrones de secrets hardcodeados!"
else
    success "No se encontraron secrets hardcodeados"
fi

# ── Resumen Final ────────────────────────────────────────────
header "📊 RESUMEN DE SEGURIDAD"

echo -e "  Reports guardados en: ${CYAN}$REPORT_DIR/${NC}"
echo ""

if [ $TOTAL_ISSUES -gt 0 ]; then
    fail "Total de issues encontrados: $TOTAL_ISSUES"
    echo ""
    echo -e "  ${YELLOW}Esto es esperado — la app vulnerable tiene issues a propósito${NC}"
    echo -e "  ${CYAN}Compara vulnerable_app/app.py rutas /user vs /user/safe${NC}"
else
    success "Scan completado"
fi

echo ""
echo -e "${BOLD}💡 Próximo paso: Ejecutar Claude Code para review inteligente${NC}"
echo "   claude -p 'Review vulnerable_app/app.py for security issues'"
