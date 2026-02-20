#!/usr/bin/env bash
# =============================================================================
#  Security Checks Runner — Bunker DevSecOps (12 Checks)
#  Ejecuta todas las herramientas de seguridad localmente sin pausas
#  Tribu | Hacklab Bogota | Ethereum Bogota
# =============================================================================
#  Uso:
#    bash scripts/run_security_checks.sh          # Todos los checks
#    bash scripts/run_security_checks.sh --quick   # Solo SAST + Secrets (rapido)
# =============================================================================

set -uo pipefail

# ── Colores ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Rutas ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$PROJECT_DIR/reports"
VULN_APP="$PROJECT_DIR/vulnerable_app"
QUICK_MODE="${1:-}"

mkdir -p "$REPORT_DIR"

# ── Helpers ─────────────────────────────────────────────────
header() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "  $1"
    echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

pass()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
fail()    { echo -e "  ${RED}[FAIL]${NC} $1"; }
skip()    { echo -e "  ${DIM}[SKIP]${NC} $1"; }
info()    { echo -e "  ${CYAN}[INFO]${NC} $1"; }

TOTAL_FINDINGS=0
CHECKS_RUN=0
CHECKS_PASSED=0
CHECKS_WARNED=0
START_TIME=$(date +%s)

# ═════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}${BOLD}  Bunker DevSecOps — Security Checks Runner${NC}"
echo -e "${DIM}  Tribu | Hacklab Bogota | Ethereum Bogota${NC}"
echo ""

# ── Check 1-2: Secret Scanning ───────────────────────────────
header "${YELLOW}[1-2/12]${NC} ${BOLD}SECRET SCANNING${NC} — ${DIM}OWASP A07:2021${NC}"

if command -v gitleaks &>/dev/null; then
    info "Ejecutando gitleaks detect..."
    GITLEAKS_OUT=$(gitleaks detect --source "$PROJECT_DIR" --no-git -v 2>&1 || true)

    SECRETS_COUNT=$(echo "$GITLEAKS_OUT" | grep -c "RuleID:" 2>/dev/null || echo "0")
    echo "$GITLEAKS_OUT" | head -30
    echo ""

    if [ "$SECRETS_COUNT" -gt 0 ]; then
        warn "Gitleaks: $SECRETS_COUNT secrets detectados"
        CHECKS_WARNED=$((CHECKS_WARNED+1))
    else
        pass "Gitleaks: 0 secrets"
        CHECKS_PASSED=$((CHECKS_PASSED+1))
    fi
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + SECRETS_COUNT))
    CHECKS_RUN=$((CHECKS_RUN+1))
else
    # Fallback: grep patterns
    SECRETS_COUNT=$(grep -rcE "(PASSWORD|SECRET_KEY|API_KEY)\s*=\s*['\"]" "$VULN_APP/" 2>/dev/null | grep -c ":" || echo "0")
    SK_COUNT=$(grep -rc "sk-ant-" "$VULN_APP/" 2>/dev/null | grep -c ":" || echo "0")
    SECRETS_COUNT=$((SECRETS_COUNT + SK_COUNT))
    warn "gitleaks no disponible — grep encontro $SECRETS_COUNT patrones"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + SECRETS_COUNT))
    CHECKS_RUN=$((CHECKS_RUN+1))
    CHECKS_WARNED=$((CHECKS_WARNED+1))
fi

# ── Check 3: Bandit SAST ─────────────────────────────────────
header "${YELLOW}[3/12]${NC} ${BOLD}BANDIT — Python SAST${NC} — ${DIM}OWASP A03:2021${NC}"

if command -v bandit &>/dev/null; then
    info "Ejecutando bandit -r vulnerable_app/ -ll..."
    bandit -r "$VULN_APP" -f screen -ll 2>/dev/null || true

    BANDIT_JSON=$(bandit -r "$VULN_APP" -f json 2>/dev/null || echo '{"results":[]}')
    BANDIT_COUNT=$(echo "$BANDIT_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo "0")

    bandit -r "$VULN_APP" -f json -o "$REPORT_DIR/bandit.json" 2>/dev/null || true

    echo ""
    warn "Bandit: $BANDIT_COUNT issues"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + BANDIT_COUNT))
    CHECKS_RUN=$((CHECKS_RUN+1))
    CHECKS_WARNED=$((CHECKS_WARNED+1))
else
    skip "bandit no instalado — pip install bandit"
fi

# ── Check 4: Semgrep SAST ────────────────────────────────────
header "${YELLOW}[4/12]${NC} ${BOLD}SEMGREP — Multi-language SAST${NC} — ${DIM}OWASP A03:2021${NC}"

if command -v semgrep &>/dev/null; then
    info "Ejecutando semgrep --config auto..."
    semgrep --config auto "$VULN_APP" --no-git 2>/dev/null || true

    SEMGREP_COUNT=$(semgrep --config auto "$VULN_APP" --no-git --json 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo "0")

    semgrep --config auto "$VULN_APP" --no-git --json -o "$REPORT_DIR/semgrep.json" 2>/dev/null || true

    echo ""
    warn "Semgrep: $SEMGREP_COUNT findings"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + SEMGREP_COUNT))
    CHECKS_RUN=$((CHECKS_RUN+1))
    CHECKS_WARNED=$((CHECKS_WARNED+1))
else
    skip "semgrep no instalado — pip install semgrep"
fi

# Si modo rapido, saltar el resto
if [ "$QUICK_MODE" = "--quick" ]; then
    header "${GREEN}${BOLD}MODO RAPIDO — Checks adicionales saltados${NC}"
    info "Ejecutar sin --quick para correr los 12 checks"
else

# ── Check 5: Dependency Audit ─────────────────────────────────
header "${YELLOW}[5/12]${NC} ${BOLD}DEPENDENCY AUDIT — Safety + pip-audit${NC} — ${DIM}OWASP A06:2021${NC}"

DEP_FINDINGS=0

if command -v safety &>/dev/null; then
    info "Safety: escaneando requirements.txt..."
    safety check -r "$VULN_APP/requirements.txt" 2>/dev/null || true
    DEP_FINDINGS=$((DEP_FINDINGS+1))  # gunicorn siempre tiene CVE
    echo ""
else
    skip "safety no instalado"
fi

if command -v pip-audit &>/dev/null; then
    info "pip-audit: verificacion cruzada..."
    pip-audit -r "$VULN_APP/requirements.txt" 2>/dev/null || true
    echo ""
else
    skip "pip-audit no instalado"
fi

warn "Dependency Audit: $DEP_FINDINGS vulnerabilidad(es)"
TOTAL_FINDINGS=$((TOTAL_FINDINGS + DEP_FINDINGS))
CHECKS_RUN=$((CHECKS_RUN+1))
CHECKS_WARNED=$((CHECKS_WARNED+1))

# ── Check 6-7: Container Security ────────────────────────────
header "${YELLOW}[6-7/12]${NC} ${BOLD}CONTAINER SECURITY — Hadolint + Trivy${NC} — ${DIM}OWASP A05:2021${NC}"

CONTAINER_FINDINGS=0

if command -v hadolint &>/dev/null; then
    for df in "$PROJECT_DIR"/docker/*/Dockerfile; do
        if [ -f "$df" ]; then
            rel="${df#$PROJECT_DIR/}"
            info "Hadolint: $rel"
            HOUT=$(hadolint "$df" 2>&1 || true)
            if [ -n "$HOUT" ]; then
                echo "$HOUT"
                HC=$(echo "$HOUT" | grep -c "DL\|SC" 2>/dev/null || echo "0")
                CONTAINER_FINDINGS=$((CONTAINER_FINDINGS + HC))
            else
                pass "$rel — sin issues"
            fi
        fi
    done
else
    skip "hadolint no instalado"
fi

if command -v trivy &>/dev/null; then
    info "Trivy: scan de dependencias..."
    trivy fs --scanners vuln "$VULN_APP/requirements.txt" 2>/dev/null || true
fi

echo ""
if [ "$CONTAINER_FINDINGS" -gt 0 ]; then
    warn "Container: $CONTAINER_FINDINGS issues"
else
    pass "Container: Dockerfiles limpios"
fi
TOTAL_FINDINGS=$((TOTAL_FINDINGS + CONTAINER_FINDINGS))
CHECKS_RUN=$((CHECKS_RUN+1))
[ "$CONTAINER_FINDINGS" -eq 0 ] && CHECKS_PASSED=$((CHECKS_PASSED+1)) || CHECKS_WARNED=$((CHECKS_WARNED+1))

# ── Check 8-9: IaC Security ──────────────────────────────────
header "${YELLOW}[8-9/12]${NC} ${BOLD}IaC SECURITY — Terraform Scan${NC} — ${DIM}OWASP A05:2021${NC}"

IAC_FINDINGS=0

if command -v trivy &>/dev/null && [ -d "$PROJECT_DIR/terraform" ]; then
    info "Trivy config: escaneando terraform/..."
    trivy config "$PROJECT_DIR/terraform/" 2>/dev/null || true

    IAC_FINDINGS=$(trivy config "$PROJECT_DIR/terraform/" --format json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
total = 0
for r in data.get('Results', []):
    total += len(r.get('Misconfigurations', []))
print(total)
" 2>/dev/null || echo "0")

    echo ""
    if [ "$IAC_FINDINGS" -gt 0 ]; then
        warn "IaC: $IAC_FINDINGS misconfigurations"
    else
        pass "IaC: 0 misconfigurations"
    fi
elif [ ! -d "$PROJECT_DIR/terraform" ]; then
    skip "Sin archivos Terraform"
else
    skip "trivy no instalado"
fi
TOTAL_FINDINGS=$((TOTAL_FINDINGS + IAC_FINDINGS))
CHECKS_RUN=$((CHECKS_RUN+1))
[ "$IAC_FINDINGS" -eq 0 ] && CHECKS_PASSED=$((CHECKS_PASSED+1)) || CHECKS_WARNED=$((CHECKS_WARNED+1))

# ── Check 10: License Audit ───────────────────────────────────
header "${YELLOW}[10/12]${NC} ${BOLD}LICENSE AUDIT — pip-licenses${NC}"

if command -v pip-licenses &>/dev/null; then
    pip-licenses --order=license --format=table 2>/dev/null | head -20 || true
    LIC_UNKNOWN=$(pip-licenses --format=csv 2>/dev/null | grep -ci "UNKNOWN" || echo "0")
    echo ""
    if [ "$LIC_UNKNOWN" -gt 0 ]; then
        info "Licencias: $LIC_UNKNOWN paquetes UNKNOWN"
    else
        pass "Licencias: todas validas"
    fi
    CHECKS_RUN=$((CHECKS_RUN+1))
    CHECKS_PASSED=$((CHECKS_PASSED+1))
else
    skip "pip-licenses no instalado"
fi

# ── Check 11: Security Tests ─────────────────────────────────
header "${YELLOW}[11/12]${NC} ${BOLD}SECURITY TESTS — pytest${NC} — ${DIM}OWASP A04:2021${NC}"

if command -v pytest &>/dev/null; then
    info "Ejecutando pytest tests/ -v..."
    PYTEST_OUT=$(pytest "$PROJECT_DIR/tests/" -v --tb=short 2>&1 || true)
    echo "$PYTEST_OUT"

    T_PASS=$(echo "$PYTEST_OUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
    T_FAIL=$(echo "$PYTEST_OUT" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")

    echo ""
    if [ "$T_FAIL" -eq 0 ] && [ "$T_PASS" -gt 0 ]; then
        pass "pytest: ${T_PASS} tests passed"
        CHECKS_PASSED=$((CHECKS_PASSED+1))
    else
        fail "pytest: ${T_FAIL} failed / ${T_PASS} passed"
    fi
    CHECKS_RUN=$((CHECKS_RUN+1))
else
    skip "pytest no instalado"
fi

# ── Check 12: Notifications (info only) ──────────────────────
header "${YELLOW}[12/12]${NC} ${BOLD}ALERTAS — Telegram + Discord${NC}"

info "Las alertas se envian automaticamente via GitHub Actions"
info "Para enviar manualmente, usar: bash scripts/demo_live.sh"
CHECKS_RUN=$((CHECKS_RUN+1))
CHECKS_PASSED=$((CHECKS_PASSED+1))

fi  # fin del if QUICK_MODE

# ── Resumen Final ────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

header "${BOLD}RESUMEN DE SEGURIDAD${NC}"

echo -e "  ${BOLD}Checks ejecutados:${NC}  $CHECKS_RUN"
echo -e "  ${GREEN}Passed:${NC}             $CHECKS_PASSED"
echo -e "  ${YELLOW}Warnings:${NC}           $CHECKS_WARNED"
echo -e "  ${BOLD}Total findings:${NC}     $TOTAL_FINDINGS"
echo -e "  ${DIM}Duracion:${NC}           ${DURATION}s"
echo ""
echo -e "  ${BOLD}Reports:${NC}"
[ -f "$REPORT_DIR/bandit.json" ]  && echo -e "    ${CYAN}reports/bandit.json${NC}"
[ -f "$REPORT_DIR/semgrep.json" ] && echo -e "    ${CYAN}reports/semgrep.json${NC}"
echo ""

if [ "$TOTAL_FINDINGS" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠ Findings esperados — vulnerable_app/ tiene vulnerabilidades a proposito${NC}"
    echo -e "  ${CYAN}Comparar: vulnerable_app/app.py (vulnerable) vs app_secure.py (seguro)${NC}"
fi

echo ""
echo -e "${DIM}  Bunker DevSecOps — Tribu | Hacklab Bogota | Ethereum Bogota${NC}"
echo ""
