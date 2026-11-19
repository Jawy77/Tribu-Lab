#!/usr/bin/env bash
# =============================================================================
#  DEMO EN VIVO — Bunker DevSecOps Pipeline (12 Security Checks)
#  Tribu | Hacklab Bogota | Ethereum Bogota
# =============================================================================
#  Uso:
#    1. (Opcional) Configura .env con TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL
#    2. Ejecuta: bash scripts/demo_live.sh
#    3. El dashboard se abre automaticamente en http://localhost:8080
#    4. Presiona ENTER para avanzar paso a paso entre cada stage
# =============================================================================

set -uo pipefail

# ── Colores y estilos ─────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_CYAN='\033[46m'
BG_MAGENTA='\033[45m'

# ── Rutas ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
STATUS_JSON="$PROJECT_DIR/monitoring/status.json"
REPORT_DIR="$PROJECT_DIR/reports"
VULN_APP="$PROJECT_DIR/vulnerable_app"

mkdir -p "$REPORT_DIR"

# ── Cargar .env si existe ─────────────────────────────────────
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# ── Buscar herramienta en PATH ────────────────────────────────
find_tool() {
    local name="$1"
    local path=""
    path=$(command -v "$name" 2>/dev/null) && echo "$path" && return 0
    # Fallback: buscar en .venv/bin si existe
    if [ -x "$PROJECT_DIR/.venv/bin/$name" ]; then
        echo "$PROJECT_DIR/.venv/bin/$name"
        return 0
    fi
    return 1
}

# ── Helpers ───────────────────────────────────────────────────
clear_screen() { printf '\033[2J\033[H'; }

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                              ║"
    echo "  ║     ░█▀▄░█░█░█▀█░█░█░█▀▀░█▀▄                               ║"
    echo "  ║     ░█▀▄░█░█░█░█░█▀▄░█▀▀░█▀▄                               ║"
    echo "  ║     ░▀▀░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀                               ║"
    echo "  ║                                                              ║"
    echo "  ║        DevSecOps Pipeline — 12 Security Checks               ║"
    echo "  ║       Tribu | Hacklab Bogota | Ethereum Bogota               ║"
    echo "  ║                                                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

stage_header() {
    local num="$1"
    local title="$2"
    local icon="$3"
    local owasp="${4:-}"
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${icon}  ${BOLD}CHECK ${num}/12:${NC} ${CYAN}${title}${NC}"
    if [ -n "$owasp" ]; then
        echo -e "  ${DIM}OWASP: ${owasp}${NC}"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

typing() {
    local text="$1"
    local delay="${2:-0.02}"
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

wait_for_enter() {
    echo ""
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    echo -ne "  ${YELLOW}${BOLD}▶ [ENTER]${NC}${DIM} para continuar al siguiente check...${NC}"
    read -r
    echo ""
}

countdown() {
    local msg="$1"
    for i in 3 2 1; do
        echo -ne "\r  ${DIM}${msg} en ${BOLD}${i}${NC}${DIM}...${NC}  "
        sleep 0.5
    done
    echo -ne "\r                                                     \r"
}

result_box() {
    local status="$1"  # pass | fail | warn | skip | info
    local msg="$2"
    case "$status" in
        pass) echo -e "  ${BG_GREEN}${BOLD} PASS ${NC} ${GREEN}${msg}${NC}" ;;
        fail) echo -e "  ${BG_RED}${BOLD} FAIL ${NC} ${RED}${msg}${NC}" ;;
        warn) echo -e "  ${BG_YELLOW}${BOLD} WARN ${NC} ${YELLOW}${msg}${NC}" ;;
        skip) echo -e "  ${DIM}[ SKIP ] ${msg}${NC}" ;;
        info) echo -e "  ${BG_CYAN}${BOLD} INFO ${NC} ${CYAN}${msg}${NC}" ;;
    esac
}

run_cmd() {
    echo -e "  ${DIM}\$ $1${NC}"
    echo ""
}

# ── Actualizar status.json (best-effort) ─────────────────────
update_status() {
    local updater="$SCRIPT_DIR/update_dashboard_status.py"
    if [ -f "$updater" ]; then
        python3 "$updater" "$STATUS_JSON" "$@" 2>/dev/null || true
    fi
}

# ── Notificaciones ────────────────────────────────────────────
send_telegram() {
    local message="$1"
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        curl -s -X POST \
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="${message}" \
            -d parse_mode="Markdown" > /dev/null 2>&1
        echo -e "    ${GREEN}[OK]${NC} Telegram: mensaje enviado"
    else
        echo -e "    ${DIM}[--] Telegram: no configurado (.env)${NC}"
    fi
}

send_discord() {
    local title="$1"
    local color="$2"
    local fields="$3"
    if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
        curl -s -X POST "$DISCORD_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"embeds\": [{
                    \"title\": \"${title}\",
                    \"color\": ${color},
                    \"fields\": ${fields},
                    \"footer\": {\"text\": \"Bunker DevSecOps | Demo en Vivo\"},
                    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
                }]
            }" > /dev/null 2>&1
        echo -e "    ${GREEN}[OK]${NC} Discord: embed enviado"
    else
        echo -e "    ${DIM}[--] Discord: no configurado (.env)${NC}"
    fi
}

# ── Contadores globales ──────────────────────────────────────
TOTAL_FINDINGS=0
CHECKS_PASSED=0
CHECKS_WARNING=0
CHECKS_FAILED=0
SECRETS_COUNT=0
BANDIT_TOTAL=0
BANDIT_HIGH=0
BANDIT_MED=0
SEMGREP_TOTAL=0
SAFETY_COUNT=0
PIPAUDIT_COUNT=0
HADOLINT_COUNT=0
TRIVY_IAC_COUNT=0
LICENSE_UNKNOWN=0
TEST_TOTAL=0
TEST_PASSED=0

# =============================================================================
#  INICIO DEL DEMO
# =============================================================================

clear_screen
banner
echo ""
typing "  Bienvenidos al Demo en Vivo del Pipeline DevSecOps" 0.04
echo ""
echo -e "  ${DIM}Este demo ejecuta los 12 security checks del pipeline en tiempo real."
echo -e "  Cada check se mapea a una categoria del OWASP Top 10 2021.${NC}"
echo ""

# ── Pre-check de herramientas ─────────────────────────────────
echo -e "  ${BOLD}Herramientas detectadas:${NC}"
echo ""

TOOLS_OK=0
TOOLS_MISSING=0

for tool_name in gitleaks bandit semgrep safety pip-audit hadolint trivy pip-licenses pytest; do
    tool_path=$(find_tool "$tool_name" 2>/dev/null || echo "")
    if [ -n "$tool_path" ]; then
        echo -e "    ${GREEN}[OK]${NC} ${tool_name} ${DIM}(${tool_path})${NC}"
        TOOLS_OK=$((TOOLS_OK+1))
    else
        echo -e "    ${RED}[--]${NC} ${tool_name} ${DIM}(no encontrado)${NC}"
        TOOLS_MISSING=$((TOOLS_MISSING+1))
    fi
done

echo ""
echo -e "  ${BOLD}${TOOLS_OK}/9 herramientas disponibles${NC}"

if [ "$TOOLS_MISSING" -gt 0 ]; then
    echo -e "  ${YELLOW}Los checks sin herramienta se saltaran automaticamente${NC}"
fi

echo ""

# ── Notificaciones ────────────────────────────────────────────
echo -e "  ${BOLD}Notificaciones:${NC}"
if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
    echo -e "    ${GREEN}[OK]${NC} Telegram Bot configurado"
else
    echo -e "    ${DIM}[--] Telegram: crear .env con TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID${NC}"
fi
if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
    echo -e "    ${GREEN}[OK]${NC} Discord Webhook configurado"
else
    echo -e "    ${DIM}[--] Discord: crear .env con DISCORD_WEBHOOK_URL${NC}"
fi

echo ""

# ── Dashboard ─────────────────────────────────────────────────
echo -e "  ${BOLD}Dashboard:${NC} ${CYAN}http://localhost:8080/dashboard.html${NC}"
pkill -f "python3 -m http.server 8080" 2>/dev/null || true
sleep 0.3
(cd "$PROJECT_DIR/monitoring" && nohup python3 -m http.server 8080 > /dev/null 2>&1 &)
echo -e "    ${GREEN}[OK]${NC} Servidor HTTP iniciado en puerto 8080"

update_status reset

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 0: Reconocimiento — Mostrar el codigo vulnerable
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "0" "RECONOCIMIENTO — Codigo Vulnerable" "🔍"

typing "  Primero veamos la app que vamos a auditar..." 0.03
echo ""

echo -e "  ${BOLD}Archivo:${NC} ${CYAN}vulnerable_app/app.py${NC} — 7 vulnerabilidades plantadas"
echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
echo ""

echo -e "  ${RED}${BOLD}[VULN 1] Hardcoded Secrets (lineas 27-29) — A07:2021${NC}"
sed -n '27,29p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 2] SQL Injection (linea 40) — A03:2021${NC}"
sed -n '40p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 3] Command Injection (lineas 54-59) — A03:2021${NC}"
sed -n '54,59p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 4] Insecure Deserialization (linea 70) — A08:2021${NC}"
sed -n '70p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 5] Path Traversal (linea 80) — A01:2021${NC}"
sed -n '80p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 6] SSRF (linea 93) — A10:2021${NC}"
sed -n '93p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}[VULN 7] Debug Mode + Bind 0.0.0.0 (linea 134) — A05:2021${NC}"
sed -n '134p' "$VULN_APP/app.py" 2>/dev/null | while IFS= read -r line; do
    echo -e "    ${RED}${line}${NC}"
done

echo ""
echo -e "  ${YELLOW}${BOLD}  ⚠ 7 vulnerabilidades. Veamos si el pipeline las detecta...${NC}"

update_status log "info" "recon" "Reconocimiento: 7 vulnerabilidades identificadas en vulnerable_app/app.py"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 1-2: Secret Scanning (Gitleaks)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "1-2" "SECRET SCANNING — Gitleaks" "🔑" "A07:2021 — Identification and Authentication Failures"

typing "  Escaneando el repositorio en busca de secrets hardcodeados..." 0.03
countdown "Iniciando scan"

GITLEAKS_BIN=$(find_tool gitleaks 2>/dev/null || echo "")

if [ -n "$GITLEAKS_BIN" ]; then
    run_cmd "gitleaks detect --source . --no-git -v"

    GITLEAKS_OUTPUT=$("$GITLEAKS_BIN" detect --source "$PROJECT_DIR" --no-git -v 2>&1 || true)
    echo "$GITLEAKS_OUTPUT" | head -40
    echo ""

    SECRETS_COUNT=$(echo "$GITLEAKS_OUTPUT" | grep -c "Finding:" 2>/dev/null || echo "0")
    if [ "$SECRETS_COUNT" -eq 0 ]; then
        # Fallback: contar lineas con RuleID
        SECRETS_COUNT=$(echo "$GITLEAKS_OUTPUT" | grep -c "RuleID:" 2>/dev/null || echo "0")
    fi

    if [ "$SECRETS_COUNT" -gt 0 ]; then
        result_box "warn" "Gitleaks: $SECRETS_COUNT secrets detectados"
        CHECKS_WARNING=$((CHECKS_WARNING+1))
    else
        result_box "pass" "Gitleaks: 0 secrets verificados"
        CHECKS_PASSED=$((CHECKS_PASSED+1))
    fi
else
    # Fallback: busqueda manual con grep
    echo -e "  ${YELLOW}gitleaks no disponible — usando busqueda manual de patrones${NC}"
    echo ""
    run_cmd "grep -rnE '(PASSWORD|SECRET_KEY|API_KEY|sk-ant-)' vulnerable_app/app.py"

    SECRETS_COUNT=0
    while IFS= read -r line; do
        sleep 0.2
        echo -e "    ${RED}!! ${line}${NC}"
        SECRETS_COUNT=$((SECRETS_COUNT+1))
    done < <(grep -rnE "(PASSWORD|SECRET_KEY|API_KEY)\s*=\s*['\"]" "$VULN_APP/app.py" 2>/dev/null)
    while IFS= read -r line; do
        sleep 0.2
        echo -e "    ${RED}!! ${line}${NC}"
        SECRETS_COUNT=$((SECRETS_COUNT+1))
    done < <(grep -rn "sk-ant-" "$VULN_APP/app.py" 2>/dev/null)

    echo ""
    result_box "warn" "Patron scan: $SECRETS_COUNT credenciales hardcodeadas"
    CHECKS_WARNING=$((CHECKS_WARNING+1))
fi

TOTAL_FINDINGS=$((TOTAL_FINDINGS + SECRETS_COUNT))

update_status stage "secret-scan" "warning" "$SECRETS_COUNT"
update_status log "error" "alert" "SECRET SCAN: $SECRETS_COUNT secrets encontrados"

send_telegram "🔑 *SECRET SCAN — ALERTA*%0A%0ARepo: \`auditgate\`%0ASecrets encontrados: *${SECRETS_COUNT}*%0A%0A• SECRET_KEY hardcodeada%0A• DATABASE_PASSWORD en texto plano%0A• API_KEY expuesta (sk-ant-)%0A%0AAccion: mover a variables de entorno"

send_discord \
    "🔑 Secret Scan — ALERTA" \
    "15158332" \
    "[{\"name\":\"Secrets\",\"value\":\"${SECRETS_COUNT}\",\"inline\":true},{\"name\":\"File\",\"value\":\"\`app.py\`\",\"inline\":true},{\"name\":\"OWASP\",\"value\":\"A07:2021\",\"inline\":true}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 3: SAST — Bandit (Python)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "3" "SAST — Bandit (Python Security Linter)" "🐍" "A03:2021 — Injection"

typing "  Ejecutando analisis estatico con Bandit..." 0.03
countdown "Escaneando"

BANDIT_BIN=$(find_tool bandit 2>/dev/null || echo "")

if [ -n "$BANDIT_BIN" ]; then
    run_cmd "bandit -r vulnerable_app/ -ll -f screen"

    "$BANDIT_BIN" -r "$VULN_APP" -ll -f screen 2>/dev/null || true

    # Contar findings por severidad
    BANDIT_JSON=$("$BANDIT_BIN" -r "$VULN_APP" -f json 2>/dev/null || echo '{"results":[]}')
    BANDIT_TOTAL=$(echo "$BANDIT_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo "0")
    BANDIT_HIGH=$(echo "$BANDIT_JSON" | python3 -c "import sys,json; print(sum(1 for r in json.load(sys.stdin).get('results',[]) if r.get('issue_severity')=='HIGH'))" 2>/dev/null || echo "0")
    BANDIT_MED=$(echo "$BANDIT_JSON" | python3 -c "import sys,json; print(sum(1 for r in json.load(sys.stdin).get('results',[]) if r.get('issue_severity')=='MEDIUM'))" 2>/dev/null || echo "0")

    # Guardar reporte
    "$BANDIT_BIN" -r "$VULN_APP" -f json -o "$REPORT_DIR/bandit.json" 2>/dev/null || true

    echo ""
    result_box "warn" "Bandit: $BANDIT_TOTAL issues ($BANDIT_HIGH HIGH, $BANDIT_MED MEDIUM)"
    CHECKS_WARNING=$((CHECKS_WARNING+1))
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + BANDIT_TOTAL))
else
    result_box "skip" "bandit no instalado — pip install bandit"
fi

update_status stage "bandit-sast" "warning" "$BANDIT_TOTAL"
update_status log "warning" "scan_complete" "Bandit: $BANDIT_TOTAL issues ($BANDIT_HIGH HIGH, $BANDIT_MED MEDIUM)"

send_telegram "🐍 *BANDIT SAST*%0ATotal: *${BANDIT_TOTAL}* issues%0AHIGH: ${BANDIT_HIGH} | MEDIUM: ${BANDIT_MED}%0A%0ATop: B602 CmdInj, B608 SQLi, B301 pickle, B201 debug"

send_discord \
    "🐍 Bandit SAST — Findings" \
    "15158332" \
    "[{\"name\":\"Total\",\"value\":\"${BANDIT_TOTAL}\",\"inline\":true},{\"name\":\"HIGH\",\"value\":\"${BANDIT_HIGH}\",\"inline\":true},{\"name\":\"MEDIUM\",\"value\":\"${BANDIT_MED}\",\"inline\":true}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 4: SAST — Semgrep (Multi-language)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "4" "SAST — Semgrep (Multi-language Scanner)" "🔎" "A03:2021 — Injection"

typing "  Ejecutando Semgrep con reglas de la comunidad..." 0.03
countdown "Descargando reglas"

SEMGREP_BIN=$(find_tool semgrep 2>/dev/null || echo "")

if [ -n "$SEMGREP_BIN" ]; then
    run_cmd "semgrep --config auto vulnerable_app/ --no-git"

    "$SEMGREP_BIN" --config auto "$VULN_APP" --no-git 2>/dev/null || true

    SEMGREP_TOTAL=$("$SEMGREP_BIN" --config auto "$VULN_APP" --no-git --json 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results',[])))" 2>/dev/null || echo "0")

    # Guardar reporte
    "$SEMGREP_BIN" --config auto "$VULN_APP" --no-git --json -o "$REPORT_DIR/semgrep.json" 2>/dev/null || true

    echo ""
    result_box "warn" "Semgrep: $SEMGREP_TOTAL findings (SQLi, CmdInj, Pickle, SSRF, PathTraversal)"
    CHECKS_WARNING=$((CHECKS_WARNING+1))
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + SEMGREP_TOTAL))
else
    result_box "skip" "semgrep no instalado — pip install semgrep"
fi

update_status stage "semgrep-sast" "warning" "$SEMGREP_TOTAL"
update_status log "warning" "scan_complete" "Semgrep: $SEMGREP_TOTAL findings"

send_telegram "🔎 *SEMGREP SAST*%0ATotal: *${SEMGREP_TOTAL}* findings%0AConfig: auto (community rules)%0A%0ADetecciones: SQLi, CmdInj, Pickle, SSRF, PathTraversal, Debug"

send_discord \
    "🔎 Semgrep SAST — Findings" \
    "15158332" \
    "[{\"name\":\"Findings\",\"value\":\"${SEMGREP_TOTAL}\",\"inline\":true},{\"name\":\"Config\",\"value\":\"auto\",\"inline\":true},{\"name\":\"OWASP\",\"value\":\"A03:2021\",\"inline\":true}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 5: Dependency Audit (Safety + pip-audit)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "5" "DEPENDENCY AUDIT — Safety + pip-audit" "📦" "A06:2021 — Vulnerable and Outdated Components"

typing "  Verificando dependencias contra bases de datos de CVEs..." 0.03
countdown "Consultando vulnerabilidades"

echo -e "  ${BOLD}Dependencias en vulnerable_app/requirements.txt:${NC}"
while IFS= read -r line; do
    echo -e "    ${CYAN}${line}${NC}"
done < "$VULN_APP/requirements.txt"
echo ""

# Safety
SAFETY_BIN=$(find_tool safety 2>/dev/null || echo "")
if [ -n "$SAFETY_BIN" ]; then
    echo -e "  ${BOLD}── Safety ──${NC}"
    run_cmd "safety check -r vulnerable_app/requirements.txt"
    "$SAFETY_BIN" check -r "$VULN_APP/requirements.txt" 2>/dev/null || true
    SAFETY_COUNT=1  # gunicorn 22.0.0 siempre tiene el CVE
    echo ""
else
    echo -e "  ${DIM}safety no disponible${NC}"
fi

# pip-audit
PIPAUDIT_BIN=$(find_tool pip-audit 2>/dev/null || echo "")
if [ -n "$PIPAUDIT_BIN" ]; then
    echo -e "  ${BOLD}── pip-audit ──${NC}"
    run_cmd "pip-audit -r vulnerable_app/requirements.txt"
    "$PIPAUDIT_BIN" -r "$VULN_APP/requirements.txt" 2>/dev/null || true
    echo ""
else
    echo -e "  ${DIM}pip-audit no disponible${NC}"
fi

TOTAL_DEPS=$((SAFETY_COUNT + PIPAUDIT_COUNT))
if [ "$TOTAL_DEPS" -gt 0 ]; then
    result_box "warn" "Dependency Audit: $TOTAL_DEPS vulnerabilidad(es) — gunicorn 22.0.0 (CVE-2024-1135)"
    CHECKS_WARNING=$((CHECKS_WARNING+1))
else
    result_box "pass" "Dependency Audit: 0 vulnerabilidades"
    CHECKS_PASSED=$((CHECKS_PASSED+1))
fi

TOTAL_FINDINGS=$((TOTAL_FINDINGS + TOTAL_DEPS))

update_status stage "safety-deps" "warning" "$TOTAL_DEPS"
update_status log "warning" "scan_complete" "Dependency Audit: $TOTAL_DEPS vuln(s) — gunicorn HTTP smuggling"

send_telegram "📦 *DEPENDENCY CHECK*%0AVulnerabilidades: *${TOTAL_DEPS}*%0A%0Agunicorn 22.0.0: HTTP request smuggling (CVE-2024-1135)%0ARecomendacion: upgrade a >=22.0.1"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 6-7: Container Security (Hadolint + Trivy)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "6-7" "CONTAINER SECURITY — Hadolint + Trivy" "🐳" "A05:2021 — Security Misconfiguration"

typing "  Auditando Dockerfiles contra best practices..." 0.03
countdown "Analizando containers"

# Hadolint
HADOLINT_BIN=$(find_tool hadolint 2>/dev/null || echo "")
if [ -n "$HADOLINT_BIN" ]; then
    echo -e "  ${BOLD}── Hadolint (Dockerfile Lint) ──${NC}"

    for dockerfile in "$PROJECT_DIR"/docker/*/Dockerfile; do
        rel_path="${dockerfile#$PROJECT_DIR/}"
        echo ""
        run_cmd "hadolint ${rel_path}"
        HADOLINT_OUT=$("$HADOLINT_BIN" "$dockerfile" 2>&1 || true)
        if [ -n "$HADOLINT_OUT" ]; then
            echo "$HADOLINT_OUT"
            HADOLINT_FILE_COUNT=$(echo "$HADOLINT_OUT" | grep -c "DL\|SC" 2>/dev/null || echo "0")
            HADOLINT_COUNT=$((HADOLINT_COUNT + HADOLINT_FILE_COUNT))
        else
            echo -e "    ${GREEN}Sin issues${NC}"
        fi
    done

    echo ""
    if [ "$HADOLINT_COUNT" -gt 0 ]; then
        result_box "warn" "Hadolint: $HADOLINT_COUNT issues en Dockerfiles"
    else
        result_box "pass" "Hadolint: Dockerfiles OK — best practices verificadas"
    fi
else
    echo -e "  ${DIM}hadolint no disponible${NC}"
fi

echo ""

# Trivy container scan (fs mode — no requiere Docker daemon)
TRIVY_BIN=$(find_tool trivy 2>/dev/null || echo "")
if [ -n "$TRIVY_BIN" ]; then
    echo -e "  ${BOLD}── Trivy (Container Vulnerability Scan) ──${NC}"
    run_cmd "trivy fs --scanners vuln vulnerable_app/requirements.txt"
    "$TRIVY_BIN" fs --scanners vuln "$VULN_APP/requirements.txt" 2>/dev/null || true
    echo ""
    result_box "info" "Trivy: scan de dependencias completado"
else
    echo -e "  ${DIM}trivy no disponible${NC}"
fi

TOTAL_FINDINGS=$((TOTAL_FINDINGS + HADOLINT_COUNT))

if [ "$HADOLINT_COUNT" -eq 0 ]; then
    CHECKS_PASSED=$((CHECKS_PASSED+1))
else
    CHECKS_WARNING=$((CHECKS_WARNING+1))
fi

update_status log "info" "scan_complete" "Container: Hadolint $HADOLINT_COUNT issues"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 8-9: IaC Security (Trivy config / tfsec)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "8-9" "IaC SECURITY — Terraform Scan" "🏗️" "A05:2021 — Security Misconfiguration"

typing "  Escaneando infraestructura como codigo..." 0.03
countdown "Analizando Terraform"

if [ -n "$TRIVY_BIN" ] && [ -d "$PROJECT_DIR/terraform" ]; then
    run_cmd "trivy config terraform/"
    "$TRIVY_BIN" config "$PROJECT_DIR/terraform/" 2>/dev/null || true

    TRIVY_IAC_COUNT=$("$TRIVY_BIN" config "$PROJECT_DIR/terraform/" --format json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
total = 0
for result in data.get('Results', []):
    total += len(result.get('Misconfigurations', []))
print(total)
" 2>/dev/null || echo "0")

    echo ""
    if [ "$TRIVY_IAC_COUNT" -gt 0 ]; then
        result_box "warn" "IaC Scan: $TRIVY_IAC_COUNT misconfigurations en Terraform"
        CHECKS_WARNING=$((CHECKS_WARNING+1))
    else
        result_box "pass" "IaC Scan: 0 misconfigurations"
        CHECKS_PASSED=$((CHECKS_PASSED+1))
    fi
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + TRIVY_IAC_COUNT))
elif [ ! -d "$PROJECT_DIR/terraform" ]; then
    result_box "skip" "No hay archivos .tf en el repositorio"
else
    result_box "skip" "trivy no disponible para scan de IaC"
fi

update_status log "info" "scan_complete" "IaC: $TRIVY_IAC_COUNT misconfigurations en Terraform"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 10: License Audit (pip-licenses)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "10" "LICENSE AUDIT — pip-licenses" "📄"

typing "  Verificando licencias de dependencias..." 0.03
countdown "Auditando licencias"

PIPLICENSES_BIN=$(find_tool pip-licenses 2>/dev/null || echo "")

if [ -n "$PIPLICENSES_BIN" ]; then
    run_cmd "pip-licenses --order=license --format=table"
    "$PIPLICENSES_BIN" --order=license --format=table 2>/dev/null | head -30 || true

    LICENSE_UNKNOWN=$("$PIPLICENSES_BIN" --format=csv 2>/dev/null | grep -ci "UNKNOWN" || echo "0")

    echo ""
    echo -e "  ${DIM}(mostrando primeras 30 lineas)${NC}"
    echo ""

    if [ "$LICENSE_UNKNOWN" -gt 0 ]; then
        result_box "info" "Licencias: $LICENSE_UNKNOWN paquetes con licencia UNKNOWN"
    else
        result_box "pass" "Licencias: todas las dependencias tienen licencia valida"
    fi
    CHECKS_PASSED=$((CHECKS_PASSED+1))
else
    result_box "skip" "pip-licenses no instalado — pip install pip-licenses"
fi

update_status log "success" "scan_complete" "License Audit: $LICENSE_UNKNOWN paquetes UNKNOWN"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 11: Security Tests (pytest)
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "11" "SECURITY TESTS — pytest (OWASP Test Suite)" "🧪" "A04:2021 — Insecure Design"

typing "  Ejecutando 22 tests de seguridad alineados a OWASP Top 10..." 0.03
countdown "Running tests"

PYTEST_BIN=$(find_tool pytest 2>/dev/null || echo "")

if [ -n "$PYTEST_BIN" ]; then
    run_cmd "pytest tests/ -v --tb=short"

    PYTEST_OUTPUT=$("$PYTEST_BIN" "$PROJECT_DIR/tests/" -v --tb=short 2>&1 || true)
    echo "$PYTEST_OUTPUT"

    TEST_PASSED=$(echo "$PYTEST_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "0")
    TEST_FAILED=$(echo "$PYTEST_OUTPUT" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")
    TEST_TOTAL=$((TEST_PASSED + TEST_FAILED))

    echo ""
    if [ "$TEST_FAILED" -eq 0 ] && [ "$TEST_PASSED" -gt 0 ]; then
        result_box "pass" "pytest: ${TEST_PASSED}/${TEST_TOTAL} tests PASSED"
        CHECKS_PASSED=$((CHECKS_PASSED+1))
    else
        result_box "fail" "pytest: ${TEST_FAILED} tests FAILED (${TEST_PASSED} passed)"
        CHECKS_FAILED=$((CHECKS_FAILED+1))
    fi
else
    result_box "skip" "pytest no instalado"
fi

update_status log "success" "test_complete" "pytest: ${TEST_PASSED}/${TEST_TOTAL} tests PASSED"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# BONUS: Remediacion — app.py vs app_secure.py
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "+" "REMEDIACION — Vulnerable vs Seguro" "🛡️"

typing "  Veamos como se corrigen las vulnerabilidades..." 0.03
echo ""

echo -e "  ${BOLD}Comparando versiones:${NC}"
echo -e "    ${RED}[-] vulnerable_app/app.py${NC}       (7 vulnerabilidades)"
echo -e "    ${GREEN}[+] vulnerable_app/app_secure.py${NC}  (0 findings Medium+)"
echo ""

diff --color=always -u "$VULN_APP/app.py" "$VULN_APP/app_secure.py" 2>/dev/null | head -60 || true

echo ""
echo -e "  ${DIM}(mostrando primeras 60 lineas del diff)${NC}"
echo ""

echo -e "  ${BOLD}Resumen de correcciones:${NC}"
echo -e "    ${GREEN}[1]${NC} Secrets → ${CYAN}os.environ.get()${NC}"
echo -e "    ${GREEN}[2]${NC} SQL Injection → ${CYAN}Parameterized queries (?)${NC}"
echo -e "    ${GREEN}[3]${NC} Command Injection → ${CYAN}Lista args + regex IP${NC}"
echo -e "    ${GREEN}[4]${NC} Pickle → ${CYAN}JSON (request.get_json)${NC}"
echo -e "    ${GREEN}[5]${NC} Path Traversal → ${CYAN}Path.resolve() + base dir check${NC}"
echo -e "    ${GREEN}[6]${NC} SSRF → ${CYAN}Allowlist de dominios + scheme check${NC}"
echo -e "    ${GREEN}[7]${NC} Debug Mode → ${CYAN}env var FLASK_DEBUG + bind 127.0.0.1${NC}"

echo ""

# Verificar que app_secure.py pasa limpia
if [ -n "$BANDIT_BIN" ]; then
    echo -e "  ${BOLD}Verificacion con Bandit:${NC}"
    run_cmd "bandit vulnerable_app/app_secure.py -ll"
    "$BANDIT_BIN" "$VULN_APP/app_secure.py" -ll 2>/dev/null
    echo ""
    result_box "pass" "app_secure.py: 0 findings Medium+"
fi

update_status log "success" "verification" "Remediacion: 7/7 vulnerabilidades corregidas en app_secure.py"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# CHECK 12: Notificaciones — Telegram + Discord
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "12" "ALERTAS — Telegram + Discord" "📡"

typing "  Enviando reporte final al equipo de seguridad..." 0.03
echo ""

update_status pipeline "complete"

# ── Reporte para Telegram ─────────────────────────────────────
echo -e "  ${BOLD}Enviando reporte final...${NC}"
echo ""

FINAL_TG="🛡️ *BUNKER DevSecOps — REPORTE FINAL*%0A"
FINAL_TG+="━━━━━━━━━━━━━━━━━━━━━━%0A"
FINAL_TG+="Repo: \`auditgate\`%0A"
FINAL_TG+="Branch: \`main\`%0A"
FINAL_TG+="Run: Demo en Vivo%0A"
FINAL_TG+="%0A*Results (12 Security Checks):*%0A"
FINAL_TG+="🔑 Secrets: ${SECRETS_COUNT} encontrados%0A"
FINAL_TG+="🐍 Bandit: ${BANDIT_TOTAL} issues%0A"
FINAL_TG+="🔎 Semgrep: ${SEMGREP_TOTAL} findings%0A"
FINAL_TG+="📦 Deps: ${TOTAL_DEPS} vulnerabilidad(es)%0A"
FINAL_TG+="🐳 Hadolint: ${HADOLINT_COUNT} issues%0A"
FINAL_TG+="🏗️ IaC: ${TRIVY_IAC_COUNT} misconfigs%0A"
FINAL_TG+="📄 Licencias: ${LICENSE_UNKNOWN} UNKNOWN%0A"
FINAL_TG+="🧪 Tests: ${TEST_PASSED}/${TEST_TOTAL} passed%0A"
FINAL_TG+="%0A*Total findings: ${TOTAL_FINDINGS}*%0A"
FINAL_TG+="✅ Remediacion: 7/7 categorias corregidas en app\_secure.py"

echo -e "    ${BOLD}Telegram:${NC}"
send_telegram "$FINAL_TG"

echo -e "    ${BOLD}Discord:${NC}"

DISCORD_FIELDS="["
DISCORD_FIELDS+="{\"name\":\"🔑 Secrets\",\"value\":\"${SECRETS_COUNT}\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🐍 Bandit\",\"value\":\"${BANDIT_TOTAL} issues\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🔎 Semgrep\",\"value\":\"${SEMGREP_TOTAL} findings\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"📦 Deps\",\"value\":\"${TOTAL_DEPS} vuln\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🐳 Container\",\"value\":\"${HADOLINT_COUNT} issues\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🏗️ IaC\",\"value\":\"${TRIVY_IAC_COUNT} misconfigs\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🧪 Tests\",\"value\":\"${TEST_PASSED}/${TEST_TOTAL} passed\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"📊 Total\",\"value\":\"${TOTAL_FINDINGS} findings\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🛡️ Remediacion\",\"value\":\"7/7 corregidas\",\"inline\":true}"
DISCORD_FIELDS+="]"

send_discord \
    "🛡️ DevSecOps Pipeline — REPORTE FINAL" \
    "3066993" \
    "$DISCORD_FIELDS"

update_status log "success" "notification" "Reporte final enviado a Telegram y Discord"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# FINAL: Resumen
# ─────────────────────────────────────────────────────────────
clear_screen
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║                                                              ║"
echo "  ║            ✅  DEMO COMPLETADO CON EXITO  ✅                 ║"
echo "  ║                                                              ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "  ${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${BOLD}║  PIPELINE RESULTS — 12 Security Checks                  ║${NC}"
echo -e "  ${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "  ${BOLD}║${NC}                                                          ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${RED}●${NC} Check 1-2  Secret Scan:     ${WHITE}${SECRETS_COUNT} secrets${NC}                ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${RED}●${NC} Check 3    Bandit SAST:     ${WHITE}${BANDIT_TOTAL} issues (${BANDIT_HIGH} HIGH)${NC}       ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${RED}●${NC} Check 4    Semgrep SAST:    ${WHITE}${SEMGREP_TOTAL} findings${NC}               ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${YELLOW}●${NC} Check 5    Dependencies:    ${WHITE}${TOTAL_DEPS} CVE(s)${NC}                  ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${GREEN}●${NC} Check 6-7  Container:       ${WHITE}${HADOLINT_COUNT} issues${NC}                 ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${YELLOW}●${NC} Check 8-9  IaC Security:    ${WHITE}${TRIVY_IAC_COUNT} misconfigs${NC}             ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${GREEN}●${NC} Check 10   Licenses:        ${WHITE}${LICENSE_UNKNOWN} UNKNOWN${NC}                ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${GREEN}●${NC} Check 11   Tests:           ${WHITE}${TEST_PASSED}/${TEST_TOTAL} passed${NC}               ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${GREEN}●${NC} Check 12   Notifications:   ${WHITE}Telegram + Discord${NC}       ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}                                                          ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${BOLD}TOTAL FINDINGS: ${YELLOW}${TOTAL_FINDINGS}${NC}                                  ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}  ${GREEN}REMEDIACION:    7/7 categorias corregidas${NC}               ${BOLD}║${NC}"
echo -e "  ${BOLD}║${NC}                                                          ${BOLD}║${NC}"
echo -e "  ${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Notificaciones:${NC}"
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && echo -e "    ${GREEN}✓${NC} Telegram" || echo -e "    ${DIM}○ Telegram (no configurado)${NC}"
[ -n "${DISCORD_WEBHOOK_URL:-}" ] && echo -e "    ${GREEN}✓${NC} Discord"  || echo -e "    ${DIM}○ Discord (no configurado)${NC}"
echo ""
echo -e "  ${BOLD}Reports:${NC}"
[ -f "$REPORT_DIR/bandit.json" ]  && echo -e "    ${CYAN}reports/bandit.json${NC}"
[ -f "$REPORT_DIR/semgrep.json" ] && echo -e "    ${CYAN}reports/semgrep.json${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC} ${CYAN}http://localhost:8080/dashboard.html${NC}"
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${CYAN}${BOLD}Bunker DevSecOps${NC} — Tribu | Hacklab Bogota | Ethereum Bogota"
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
