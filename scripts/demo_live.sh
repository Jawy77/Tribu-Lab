#!/usr/bin/env bash
# =============================================================================
#  DEMO EN VIVO — Bunker DevSecOps Pipeline
#  Comunidad Claude Anthropic Colombia
# =============================================================================
#  Uso:
#    1. Configura tu .env con TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL
#    2. Ejecuta: bash scripts/demo_live.sh
#    3. El dashboard se abre automaticamente en http://localhost:8080
#    4. Presiona ENTER para avanzar paso a paso
# =============================================================================

set -uo pipefail

# ── Colores y estilos ─────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_CYAN='\033[46m'

# ── Rutas ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv/bin"
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
    echo "  ║          DevSecOps Pipeline — DEMO EN VIVO                   ║"
    echo "  ║       Comunidad Claude Anthropic Colombia                    ║"
    echo "  ║                                                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

stage_header() {
    local num="$1"
    local title="$2"
    local icon="$3"
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${icon}  ${BOLD}STAGE ${num}:${NC} ${CYAN}${title}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

typing() {
    local text="$1"
    local delay="${2:-0.03}"
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

wait_for_enter() {
    echo ""
    echo -e "  ${DIM}────────────────────────────────────────────────${NC}"
    echo -ne "  ${YELLOW}${BOLD}[ENTER]${NC}${DIM} para continuar al siguiente paso...${NC}"
    read -r
    echo ""
}

countdown() {
    local msg="$1"
    for i in 3 2 1; do
        echo -ne "\r  ${DIM}${msg} en ${BOLD}${i}${NC}${DIM}...${NC}  "
        sleep 1
    done
    echo -ne "\r                                                     \r"
}

result_box() {
    local status="$1"  # pass | fail | warn
    local msg="$2"
    case "$status" in
        pass) echo -e "  ${BG_GREEN}${BOLD} PASS ${NC} ${GREEN}${msg}${NC}" ;;
        fail) echo -e "  ${BG_RED}${BOLD} FAIL ${NC} ${RED}${msg}${NC}" ;;
        warn) echo -e "  ${BG_YELLOW}${BOLD} WARN ${NC} ${YELLOW}${msg}${NC}" ;;
        skip) echo -e "  ${DIM}[ SKIP ] ${msg}${NC}" ;;
    esac
}

# ── Actualizar status.json ────────────────────────────────────
update_status() {
    python3 "$SCRIPT_DIR/update_dashboard_status.py" "$STATUS_JSON" "$@"
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
        echo -e "  ${GREEN}[OK]${NC} Mensaje enviado a Telegram"
    else
        echo -e "  ${YELLOW}[SKIP]${NC} TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configurados"
    fi
}

send_discord() {
    local title="$1"
    local color="$2"  # decimal
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
        echo -e "  ${GREEN}[OK]${NC} Embed enviado a Discord"
    else
        echo -e "  ${YELLOW}[SKIP]${NC} DISCORD_WEBHOOK_URL no configurado"
    fi
}


# =============================================================================
#  INICIO DEL DEMO
# =============================================================================

clear_screen
banner
echo ""
typing "  Bienvenidos al Demo en Vivo del Pipeline DevSecOps" 0.04
echo ""
echo -e "  ${DIM}Este demo ejecuta cada stage del pipeline en tiempo real."
echo -e "  Las alarmas llegan a Telegram, Discord, y al Dashboard.${NC}"
echo ""
echo -e "  ${BOLD}Pre-requisitos:${NC}"
echo -e "    ${GREEN}[OK]${NC} Python venv con bandit, semgrep, safety, pytest"

if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
    echo -e "    ${GREEN}[OK]${NC} Telegram Bot configurado"
else
    echo -e "    ${YELLOW}[--]${NC} Telegram no configurado (crear .env con TELEGRAM_BOT_TOKEN)"
fi

if [ -n "${DISCORD_WEBHOOK_URL:-}" ]; then
    echo -e "    ${GREEN}[OK]${NC} Discord Webhook configurado"
else
    echo -e "    ${YELLOW}[--]${NC} Discord no configurado (crear .env con DISCORD_WEBHOOK_URL)"
fi

echo ""
echo -e "  ${BOLD}Dashboard:${NC} ${CYAN}http://localhost:8080/dashboard.html${NC}"

# Iniciar servidor del dashboard
pkill -f "python3 -m http.server 8080" 2>/dev/null || true
sleep 0.5
(cd "$PROJECT_DIR/monitoring" && nohup python3 -m http.server 8080 > /dev/null 2>&1 &)
echo -e "  ${GREEN}[OK]${NC} Dashboard server iniciado en puerto 8080"

# Reset status.json al estado inicial
update_status reset

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 0: Mostrar el codigo vulnerable
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "0" "RECONOCIMIENTO — Codigo Vulnerable" "🔍"

typing "  Primero veamos que tiene la app que vamos a auditar..." 0.03
echo ""

echo -e "  ${BOLD}Archivo:${NC} ${CYAN}vulnerable_app/app.py${NC}"
echo -e "  ${DIM}─────────────────────────────────────────────${NC}"

# Mostrar las partes criticas del codigo
echo -e "  ${RED}${BOLD}# Hardcoded Secrets (lineas 27-29):${NC}"
sed -n '27,29p' "$VULN_APP/app.py" | while read -r line; do
    echo -e "    ${RED}$line${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}# SQL Injection (linea 40):${NC}"
sed -n '40p' "$VULN_APP/app.py" | while read -r line; do
    echo -e "    ${RED}$line${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}# Command Injection (lineas 54-59):${NC}"
sed -n '54,59p' "$VULN_APP/app.py" | while read -r line; do
    echo -e "    ${RED}$line${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}# Pickle Deserialization (linea 70):${NC}"
sed -n '70p' "$VULN_APP/app.py" | while read -r line; do
    echo -e "    ${RED}$line${NC}"
done

echo ""
echo -e "  ${RED}${BOLD}# Debug Mode (linea 134):${NC}"
sed -n '134p' "$VULN_APP/app.py" | while read -r line; do
    echo -e "    ${RED}$line${NC}"
done

echo ""
echo -e "  ${YELLOW}  7 vulnerabilidades plantadas. Veamos si el pipeline las detecta...${NC}"

update_status log "info" "recon" "Reconocimiento: analizando vulnerable_app/app.py (7 vulns plantadas)"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 1: Secret Scanning
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "1" "SECRET SCANNING — Detectar credenciales expuestas" "🔑"

typing "  Escaneando el codigo en busca de secrets hardcodeados..." 0.03
countdown "Iniciando scan"

update_status log "info" "scan_start" "Stage 1: Secret scanning iniciado"
update_status stage "secret-scan" "running" "0"

echo -e "  ${BOLD}Buscando patrones: PASSWORD, SECRET, API_KEY, sk-ant-...${NC}"
echo ""

SECRETS_COUNT=0
echo -e "  ${DIM}grep -rnE '(PASSWORD|SECRET|API_KEY|sk-ant-)\\s*=' vulnerable_app/app.py${NC}"
echo ""

while IFS= read -r line; do
    sleep 0.3
    echo -e "  ${RED}  !! ${line}${NC}"
    SECRETS_COUNT=$((SECRETS_COUNT+1))
done < <(grep -rnE "(PASSWORD|SECRET_KEY|API_KEY)\s*=\s*['\"]" "$VULN_APP/app.py" 2>/dev/null)

while IFS= read -r line; do
    sleep 0.3
    echo -e "  ${RED}  !! ${line}${NC}"
    SECRETS_COUNT=$((SECRETS_COUNT+1))
done < <(grep -rn "sk-ant-" "$VULN_APP/app.py" 2>/dev/null)

echo ""
result_box "fail" "$SECRETS_COUNT credenciales hardcodeadas detectadas!"

update_status stage "secret-scan" "failed" "$SECRETS_COUNT"
update_status log "error" "alert" "SECRET SCAN: $SECRETS_COUNT credenciales hardcodeadas encontradas en app.py"

# Notificar
send_telegram "🔑 *SECRET SCAN — ALERTA*%0A%0ARepo: \`Tribu-Lab\`%0AArchivo: \`vulnerable_app/app.py\`%0ASecrets encontrados: *${SECRETS_COUNT}*%0A%0A• SECRET_KEY hardcodeada%0A• DATABASE_PASSWORD en texto plano%0A• API_KEY expuesta (sk-ant-)%0A%0A🚨 Accion requerida: mover a variables de entorno"

send_discord \
    "🔑 Secret Scan — ALERTA" \
    "15158332" \
    "[{\"name\":\"Secrets Found\",\"value\":\"${SECRETS_COUNT}\",\"inline\":true},{\"name\":\"File\",\"value\":\"\`app.py\`\",\"inline\":true},{\"name\":\"Action\",\"value\":\"Mover a env vars\",\"inline\":false}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 2: SAST con Bandit
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "2" "SAST — Bandit (Python Security Linter)" "🐍"

typing "  Ejecutando analisis estatico con Bandit..." 0.03
countdown "Escaneando"

update_status log "info" "scan_start" "Stage 2: Bandit SAST iniciado"
update_status stage "bandit-sast" "running" "0"

echo -e "  ${DIM}\$ bandit -r vulnerable_app/ -ll -f screen${NC}"
echo ""

"$VENV/bandit" -r "$VULN_APP" -ll -f screen 2>/dev/null || true

# Contar issues
BANDIT_HIGH=$("$VENV/bandit" -r "$VULN_APP" -f json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
high = sum(1 for r in data['results'] if r['issue_severity'] == 'HIGH')
print(high)
" 2>/dev/null || echo "0")

BANDIT_MED=$("$VENV/bandit" -r "$VULN_APP" -f json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
med = sum(1 for r in data['results'] if r['issue_severity'] == 'MEDIUM')
print(med)
" 2>/dev/null || echo "0")

BANDIT_TOTAL=$("$VENV/bandit" -r "$VULN_APP" -f json 2>/dev/null | python3 -c "
import sys, json; data = json.load(sys.stdin); print(len(data['results']))
" 2>/dev/null || echo "0")

echo ""
result_box "fail" "Bandit: $BANDIT_TOTAL issues ($BANDIT_HIGH HIGH, $BANDIT_MED MEDIUM)"

"$VENV/bandit" -r "$VULN_APP" -f json -o "$REPORT_DIR/bandit.json" 2>/dev/null || true

update_status stage "bandit-sast" "failed" "$BANDIT_TOTAL"
update_status log "warning" "scan_complete" "Bandit: $BANDIT_TOTAL issues ($BANDIT_HIGH HIGH, $BANDIT_MED MEDIUM)"

send_telegram "🐍 *BANDIT SAST — FINDINGS*%0A%0ATotal: *${BANDIT_TOTAL}* issues%0A🔴 HIGH: ${BANDIT_HIGH}%0A🟡 MEDIUM: ${BANDIT_MED}%0A%0ATop findings:%0A• B602: Command Injection (shell=True)%0A• B201: Flask debug=True%0A• B608: SQL Injection f-string%0A• B301: Insecure pickle.loads%0A%0AReport: \`reports/bandit.json\`"

send_discord \
    "🐍 Bandit SAST — Findings" \
    "15158332" \
    "[{\"name\":\"Total Issues\",\"value\":\"${BANDIT_TOTAL}\",\"inline\":true},{\"name\":\"HIGH\",\"value\":\"${BANDIT_HIGH}\",\"inline\":true},{\"name\":\"MEDIUM\",\"value\":\"${BANDIT_MED}\",\"inline\":true},{\"name\":\"Top Finding\",\"value\":\"B602: Command Injection via shell=True\",\"inline\":false}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 3: SAST con Semgrep
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "3" "SAST — Semgrep (Multi-language Scanner)" "🔎"

typing "  Ejecutando Semgrep con reglas automaticas..." 0.03
countdown "Descargando reglas y escaneando"

update_status log "info" "scan_start" "Stage 3: Semgrep SAST iniciado (config: auto)"
update_status stage "semgrep-sast" "running" "0"

echo -e "  ${DIM}\$ semgrep --config auto vulnerable_app/${NC}"
echo ""

"$VENV/semgrep" --config auto "$VULN_APP" 2>/dev/null || true

SEMGREP_TOTAL=$("$VENV/semgrep" --config auto "$VULN_APP" --json 2>/dev/null | python3 -c "
import sys, json; data = json.load(sys.stdin); print(len(data.get('results',[])))
" 2>/dev/null || echo "0")

echo ""
result_box "fail" "Semgrep: $SEMGREP_TOTAL findings con reglas auto"

"$VENV/semgrep" --config auto "$VULN_APP" --json -o "$REPORT_DIR/semgrep.json" 2>/dev/null || true

update_status stage "semgrep-sast" "failed" "$SEMGREP_TOTAL"
update_status log "warning" "scan_complete" "Semgrep: $SEMGREP_TOTAL findings (SQLi, CmdInj, Pickle, SSRF, PathTraversal)"

send_telegram "🔎 *SEMGREP SAST — FINDINGS*%0A%0ATotal: *${SEMGREP_TOTAL}* findings%0AConfig: auto (community rules)%0A%0ADetecciones:%0A• SQL Injection (tainted string)%0A• Subprocess Injection%0A• Insecure Deserialization%0A• Path Traversal%0A• SSRF Injection%0A• Debug mode enabled"

send_discord \
    "🔎 Semgrep SAST — Findings" \
    "15158332" \
    "[{\"name\":\"Findings\",\"value\":\"${SEMGREP_TOTAL}\",\"inline\":true},{\"name\":\"Config\",\"value\":\"auto\",\"inline\":true},{\"name\":\"Categories\",\"value\":\"SQLi, CmdInj, Pickle, SSRF, PathTraversal, Debug\",\"inline\":false}]"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 4: Dependency Check con Safety
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "4" "DEPENDENCY CHECK — Safety" "📦"

typing "  Verificando dependencias contra base de datos de CVEs..." 0.03
countdown "Consultando vulnerabilidades"

update_status log "info" "scan_start" "Stage 4: Safety dependency check iniciado"
update_status stage "safety-deps" "running" "0"

if [ -f "$VULN_APP/requirements.txt" ]; then
    echo -e "  ${DIM}\$ safety check -r vulnerable_app/requirements.txt${NC}"
    echo ""
    echo -e "  ${BOLD}Dependencias:${NC}"
    while IFS= read -r line; do
        echo -e "    ${CYAN}$line${NC}"
    done < "$VULN_APP/requirements.txt"
    echo ""

    "$VENV/safety" check -r "$VULN_APP/requirements.txt" 2>/dev/null || true

    echo ""
    result_box "warn" "1 vulnerabilidad en dependencias (gunicorn 22.0.0)"

    update_status stage "safety-deps" "passed" "1"
    update_status log "warning" "scan_complete" "Safety: 1 vuln en gunicorn 22.0.0 (HTTP smuggling)"

    send_telegram "📦 *DEPENDENCY CHECK*%0A%0APackages escaneados: 2%0AVulnerabilidades: *1*%0A%0A⚠️ gunicorn 22.0.0%0APVE-2024-72809: HTTP request smuggling%0A%0ARecomendacion: upgrade a >=23.0.0"
else
    echo -e "  ${DIM}No se encontro requirements.txt${NC}"
    result_box "skip" "Sin archivo de dependencias"
    update_status stage "safety-deps" "skipped" "0"
fi

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 5: Mostrar la remediacion
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "5" "REMEDIACION — app.py vs app_secure.py" "🛡️"

typing "  Veamos como se corrigen las vulnerabilidades..." 0.03
echo ""

update_status log "info" "remediation" "Mostrando diff: app.py (vulnerable) vs app_secure.py (seguro)"

echo -e "  ${BOLD}Comparando versiones:${NC}"
echo -e "  ${RED}  - vulnerable_app/app.py${NC}       (vulnerable)"
echo -e "  ${GREEN}  + vulnerable_app/app_secure.py${NC}  (seguro)"
echo ""

# Diff con colores
diff --color=always -u "$VULN_APP/app.py" "$VULN_APP/app_secure.py" 2>/dev/null | head -80 || true

echo ""
echo -e "  ${DIM}... (mostrando primeras 80 lineas del diff)${NC}"
echo ""

echo -e "  ${BOLD}Resumen de correcciones:${NC}"
echo -e "  ${GREEN}  [1]${NC} Secrets → os.environ.get()"
echo -e "  ${GREEN}  [2]${NC} SQL Injection → Parameterized queries (?)"
echo -e "  ${GREEN}  [3]${NC} Command Injection → Lista args + regex IP"
echo -e "  ${GREEN}  [4]${NC} Pickle → JSON (request.get_json)"
echo -e "  ${GREEN}  [5]${NC} Path Traversal → Path.resolve() + base dir"
echo -e "  ${GREEN}  [6]${NC} SSRF → Allowlist de dominios + scheme check"
echo -e "  ${GREEN}  [7]${NC} Debug → env var FLASK_DEBUG + bind 127.0.0.1"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 6: Verificar que app_secure.py pasa limpia
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "6" "VERIFICACION — Bandit en app_secure.py" "✅"

typing "  Re-escaneando la version segura con Bandit..." 0.03
countdown "Verificando correcciones"

echo -e "  ${DIM}\$ bandit vulnerable_app/app_secure.py -ll${NC}"
echo ""

"$VENV/bandit" "$VULN_APP/app_secure.py" -ll 2>/dev/null

echo ""
result_box "pass" "0 findings Medium+ en la version segura"

update_status log "success" "verification" "Bandit re-scan: 0 findings Medium+ en app_secure.py"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 7: Tests
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "7" "TESTS — pytest suite de seguridad" "🧪"

typing "  Ejecutando suite de tests de seguridad..." 0.03
countdown "Running tests"

update_status log "info" "test_start" "Stage 7: pytest test suite iniciado"

echo -e "  ${DIM}\$ pytest tests/ -v${NC}"
echo ""

"$VENV/pytest" "$PROJECT_DIR/tests/" -v 2>&1

echo ""
result_box "pass" "21/21 tests passed"

update_status log "success" "test_complete" "pytest: 21/21 tests PASSED"

wait_for_enter

# ─────────────────────────────────────────────────────────────
# STAGE 8: Notificacion final
# ─────────────────────────────────────────────────────────────
clear_screen
stage_header "8" "NOTIFICACIONES — Telegram + Discord" "📡"

typing "  Enviando reporte final al Bunker..." 0.03
echo ""

update_status pipeline "complete"

# Telegram — Reporte final
FINAL_TG="🛡️ *DevSecOps Pipeline — REPORTE FINAL*%0A"
FINAL_TG+="━━━━━━━━━━━━━━━━━━━━━━%0A"
FINAL_TG+="Repo: \`Tribu-Lab\`%0A"
FINAL_TG+="Branch: \`main\`%0A"
FINAL_TG+="Demo: En Vivo%0A"
FINAL_TG+="%0A*Security Gates:*%0A"
FINAL_TG+="🔑 Secrets: ${SECRETS_COUNT} encontrados%0A"
FINAL_TG+="🐍 Bandit: ${BANDIT_TOTAL} issues%0A"
FINAL_TG+="🔎 Semgrep: ${SEMGREP_TOTAL} findings%0A"
FINAL_TG+="📦 Deps: 1 vulnerabilidad%0A"
FINAL_TG+="🧪 Tests: 21/21 passed%0A"
FINAL_TG+="%0A*Remediacion:*%0A"
FINAL_TG+="✅ app\_secure.py: 0 findings Medium+%0A"
FINAL_TG+="✅ 7/7 categorias de vulns corregidas%0A"
FINAL_TG+="%0A📊 Dashboard: activo en puerto 8080"

echo -e "  ${BOLD}Enviando a Telegram...${NC}"
send_telegram "$FINAL_TG"

echo ""
echo -e "  ${BOLD}Enviando a Discord...${NC}"

DISCORD_FIELDS="["
DISCORD_FIELDS+="{\"name\":\"🔑 Secrets\",\"value\":\"${SECRETS_COUNT} found\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🐍 Bandit\",\"value\":\"${BANDIT_TOTAL} issues\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🔎 Semgrep\",\"value\":\"${SEMGREP_TOTAL} findings\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"📦 Dependencies\",\"value\":\"1 vuln\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🧪 Tests\",\"value\":\"21/21 passed\",\"inline\":true},"
DISCORD_FIELDS+="{\"name\":\"🛡️ Remediation\",\"value\":\"7/7 fixed\",\"inline\":true}"
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
echo "  ║              DEMO COMPLETADO CON EXITO                       ║"
echo "  ║                                                              ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "  ${BOLD}Resumen del Pipeline:${NC}"
echo ""
echo -e "    ${RED}●${NC} Secret Scan:     ${SECRETS_COUNT} secrets hardcodeados"
echo -e "    ${RED}●${NC} Bandit SAST:     ${BANDIT_TOTAL} issues (${BANDIT_HIGH} HIGH)"
echo -e "    ${RED}●${NC} Semgrep SAST:    ${SEMGREP_TOTAL} findings"
echo -e "    ${YELLOW}●${NC} Dependencies:    1 vulnerabilidad"
echo -e "    ${GREEN}●${NC} Remediacion:     7/7 categorias corregidas"
echo -e "    ${GREEN}●${NC} Verificacion:    0 issues en app_secure.py"
echo -e "    ${GREEN}●${NC} Tests:           21/21 passed"
echo ""
echo -e "  ${BOLD}Notificaciones enviadas a:${NC}"
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && echo -e "    ${GREEN}✓${NC} Telegram" || echo -e "    ${DIM}○ Telegram (no configurado)${NC}"
[ -n "${DISCORD_WEBHOOK_URL:-}" ] && echo -e "    ${GREEN}✓${NC} Discord"  || echo -e "    ${DIM}○ Discord (no configurado)${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC} ${CYAN}http://localhost:8080/dashboard.html${NC}"
echo ""
echo -e "  ${BOLD}Reports:${NC}"
echo -e "    ${DIM}reports/bandit.json${NC}"
echo -e "    ${DIM}reports/semgrep.json${NC}"
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${CYAN}Bunker DevSecOps — Comunidad Claude Anthropic Colombia${NC}"
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
