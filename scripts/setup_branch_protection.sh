#!/usr/bin/env bash
# =============================================================================
# Branch Protection Rules — Bunker DevSecOps
# Configura proteccion de branches via GitHub CLI (gh)
#
# Prerequisitos:
#   - gh auth login (autenticado con permisos admin)
#   - Repo: Jawy77/Tribu-Lab
#
# Uso: ./setup_branch_protection.sh
# =============================================================================

set -euo pipefail

REPO="Jawy77/Tribu-Lab"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }

# Verificar gh esta instalado y autenticado
if ! command -v gh &> /dev/null; then
    warn "gh (GitHub CLI) no esta instalado. Instalar: https://cli.github.com"
    exit 1
fi

if ! gh auth status &> /dev/null; then
    warn "No autenticado. Ejecutar: gh auth login"
    exit 1
fi

info "Configurando branch protection para $REPO"
echo ""

# ── main: Requiere PR + pipeline + 1 review ─────────────────
info "Configurando proteccion para 'main'..."

gh api -X PUT "repos/$REPO/branches/main/protection" \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "🔑 Checks 1-2 — Secret Scanning",
      "🔍 Checks 3-5 — SAST + Dependencies",
      "🐳 Checks 6-7 — Container Security",
      "🏗️ Checks 8-9 — IaC Security",
      "📄 Check 10 — License Audit",
      "🧪 Check 11 — Security Tests"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

log "main: PR requerido + pipeline debe pasar + 1 review"

# ── develop: Solo requiere pipeline ──────────────────────────
info "Configurando proteccion para 'develop'..."

gh api -X PUT "repos/$REPO/branches/develop/protection" \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": false,
    "contexts": [
      "🔑 Checks 1-2 — Secret Scanning",
      "🔍 Checks 3-5 — SAST + Dependencies",
      "🧪 Check 11 — Security Tests"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

log "develop: pipeline debe pasar (no requiere PR ni review)"

# ── feature/*: Sin restricciones (info only) ─────────────────
info "feature/*: Sin proteccion (branches efimeros de desarrollo)"
echo ""

echo "================================================================"
log "Branch protection configurado exitosamente!"
echo "================================================================"
echo ""
info "Resumen:"
echo "  main       — PR + 1 review + 12 checks deben pasar (BLOQUEA)"
echo "  develop    — Pipeline debe pasar (REPORTA, no bloquea merge)"
echo "  feature/*  — Sin restricciones (desarrollo libre)"
echo "  hotfix/*   — Sin restricciones (se mergean directo a main via PR)"
echo ""
info "Para verificar:"
echo "  gh api repos/$REPO/branches/main/protection | jq '.required_status_checks'"
