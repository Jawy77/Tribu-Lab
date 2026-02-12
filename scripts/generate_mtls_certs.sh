#!/usr/bin/env bash
# =============================================================================
# 🔐 Generador de Certificados mTLS — Búnker DevSecOps
# Comunidad Claude Anthropic Colombia
# =============================================================================
# Genera una PKI completa para Mutual TLS:
#   1. CA Root (Autoridad Certificadora propia)
#   2. Certificado del Servidor (OpenClaw/Nginx)
#   3. Certificado del Cliente (Parrot OS / Workstation)
#
# Uso: ./generate_mtls_certs.sh [output_dir]
# =============================================================================

set -euo pipefail

# ── Configuración ─────────────────────────────────────────────
CERT_DIR="${1:-./crypto/certs}"
DAYS_CA=3650        # CA válida por 10 años
DAYS_CERT=365       # Certificados válidos por 1 año
KEY_SIZE=4096       # RSA key size
COUNTRY="CO"
STATE="Bogota"
ORG="Mantishield-Workshop"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }

# ── Crear directorio de salida ────────────────────────────────
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

info "Generando PKI para Mutual TLS en: $(pwd)"
echo ""

# ── 1. Generar CA Root ────────────────────────────────────────
log "Generando CA Root..."

openssl genrsa -out ca-key.pem $KEY_SIZE 2>/dev/null

openssl req -new -x509 \
    -key ca-key.pem \
    -out ca-cert.pem \
    -days $DAYS_CA \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=Bunker-CA-Root" \
    2>/dev/null

log "CA Root generada: ca-cert.pem"

# ── 2. Generar Certificado del Servidor ───────────────────────
log "Generando certificado del Servidor (OpenClaw)..."

# Crear extensiones para el servidor
cat > server-ext.cnf << EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 10.13.13.4
IP.2 = 127.0.0.1
DNS.1 = openclaw.bunker.local
DNS.2 = localhost
EOF

openssl genrsa -out server-key.pem $KEY_SIZE 2>/dev/null

openssl req -new \
    -key server-key.pem \
    -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=openclaw.bunker.local" \
    2>/dev/null

openssl x509 -req \
    -in server.csr \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out server-cert.pem \
    -days $DAYS_CERT \
    -extensions v3_req \
    -extfile server-ext.cnf \
    2>/dev/null

log "Certificado del servidor generado: server-cert.pem"

# ── 3. Generar Certificado del Cliente ────────────────────────
log "Generando certificado del Cliente (Parrot OS)..."

cat > client-ext.cnf << EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl genrsa -out client-key.pem $KEY_SIZE 2>/dev/null

openssl req -new \
    -key client-key.pem \
    -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=parrot-workstation" \
    2>/dev/null

openssl x509 -req \
    -in client.csr \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out client-cert.pem \
    -days $DAYS_CERT \
    -extensions v3_req \
    -extfile client-ext.cnf \
    2>/dev/null

log "Certificado del cliente generado: client-cert.pem"

# ── 4. Limpieza ──────────────────────────────────────────────
rm -f *.csr *.cnf *.srl

# ── 5. Verificar la cadena ───────────────────────────────────
echo ""
info "Verificando cadena de certificados..."

openssl verify -CAfile ca-cert.pem server-cert.pem
openssl verify -CAfile ca-cert.pem client-cert.pem

# ── 6. Resumen ───────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
log "PKI generada exitosamente!"
echo "═══════════════════════════════════════════════════════"
echo ""
info "Archivos generados:"
echo "  📁 ca-cert.pem      → Certificado CA Root"
echo "  📁 ca-key.pem       → Llave privada CA (¡PROTEGER!)"
echo "  📁 server-cert.pem  → Certificado del servidor"
echo "  📁 server-key.pem   → Llave privada del servidor"
echo "  📁 client-cert.pem  → Certificado del cliente"
echo "  📁 client-key.pem   → Llave privada del cliente"
echo ""
info "Distribución:"
echo "  → Servidor (10.13.13.4): ca-cert, server-cert, server-key"
echo "  → Cliente  (10.13.13.2): ca-cert, client-cert, client-key"
echo ""
warn "NUNCA compartir las llaves privadas (.key.pem) por canales inseguros"
warn "Usar SCP a través de la VPN WireGuard para transferir archivos"
echo ""

# ── 7. Generar llaves Ed25519 para SSH ───────────────────────
info "Bonus: Generando par de llaves Ed25519 para SSH..."

SSH_DIR="../keys"
mkdir -p "$SSH_DIR"

ssh-keygen -t ed25519 \
    -C "bunker-agent@workshop" \
    -f "$SSH_DIR/bunker_ed25519" \
    -N "" \
    2>/dev/null

log "Llaves SSH Ed25519 generadas en $SSH_DIR/"
echo "  📁 bunker_ed25519      → Llave privada SSH"
echo "  📁 bunker_ed25519.pub  → Llave pública SSH"
echo ""
info "Para autorizar al agente en Parrot:"
echo "  cat $SSH_DIR/bunker_ed25519.pub >> ~/.ssh/authorized_keys"
