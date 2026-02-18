#!/usr/bin/env bash
# =============================================================================
# 🔐 Generador de Certificados mTLS — Búnker DevSecOps
# Tribu | Hacklab Bogota | Ethereum Bogota
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

ERRORS=0

# 5a. Verificar que server-cert esta firmado por la CA
if openssl verify -CAfile ca-cert.pem server-cert.pem 2>/dev/null | grep -q "OK"; then
    log "server-cert.pem: cadena valida (firmado por CA Root)"
else
    warn "server-cert.pem: FALLO en verificacion de cadena"
    ERRORS=$((ERRORS + 1))
fi

# 5b. Verificar que client-cert esta firmado por la CA
if openssl verify -CAfile ca-cert.pem client-cert.pem 2>/dev/null | grep -q "OK"; then
    log "client-cert.pem: cadena valida (firmado por CA Root)"
else
    warn "client-cert.pem: FALLO en verificacion de cadena"
    ERRORS=$((ERRORS + 1))
fi

# 5c. Verificar que el par key/cert del servidor coincide
SERVER_CERT_MOD=$(openssl x509 -in server-cert.pem -noout -modulus 2>/dev/null | openssl md5)
SERVER_KEY_MOD=$(openssl rsa -in server-key.pem -noout -modulus 2>/dev/null | openssl md5)
if [ "$SERVER_CERT_MOD" = "$SERVER_KEY_MOD" ]; then
    log "server key/cert: par coincide (modulus match)"
else
    warn "server key/cert: NO COINCIDEN"
    ERRORS=$((ERRORS + 1))
fi

# 5d. Verificar que el par key/cert del cliente coincide
CLIENT_CERT_MOD=$(openssl x509 -in client-cert.pem -noout -modulus 2>/dev/null | openssl md5)
CLIENT_KEY_MOD=$(openssl rsa -in client-key.pem -noout -modulus 2>/dev/null | openssl md5)
if [ "$CLIENT_CERT_MOD" = "$CLIENT_KEY_MOD" ]; then
    log "client key/cert: par coincide (modulus match)"
else
    warn "client key/cert: NO COINCIDEN"
    ERRORS=$((ERRORS + 1))
fi

# 5e. Verificar EKU (Extended Key Usage)
if openssl x509 -in server-cert.pem -noout -text 2>/dev/null | grep -q "TLS Web Server Authentication"; then
    log "server-cert: EKU correcto (serverAuth)"
else
    warn "server-cert: falta EKU serverAuth"
    ERRORS=$((ERRORS + 1))
fi

if openssl x509 -in client-cert.pem -noout -text 2>/dev/null | grep -q "TLS Web Client Authentication"; then
    log "client-cert: EKU correcto (clientAuth)"
else
    warn "client-cert: falta EKU clientAuth"
    ERRORS=$((ERRORS + 1))
fi

# 5f. Mostrar fechas de expiracion
echo ""
info "Fechas de expiracion:"
echo "  CA Root:     $(openssl x509 -in ca-cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)"
echo "  Server cert: $(openssl x509 -in server-cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)"
echo "  Client cert: $(openssl x509 -in client-cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)"

# 5g. Mostrar SAN del server cert
echo ""
info "Subject Alternative Names (server):"
openssl x509 -in server-cert.pem -noout -text 2>/dev/null | grep -A1 "Subject Alternative" | tail -1 | sed 's/^[[:space:]]*/  /'

# ── 6. Resumen ───────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
if [ "$ERRORS" -eq 0 ]; then
    log "PKI generada y verificada exitosamente! (${ERRORS} errores)"
else
    warn "PKI generada con ${ERRORS} error(es) — revisar output"
fi
echo "═══════════════════════════════════════════════════════"
echo ""
info "Archivos generados:"
echo "  ca-cert.pem      — Certificado CA Root"
echo "  ca-key.pem       — Llave privada CA (PROTEGER)"
echo "  server-cert.pem  — Certificado del servidor"
echo "  server-key.pem   — Llave privada del servidor"
echo "  client-cert.pem  — Certificado del cliente"
echo "  client-key.pem   — Llave privada del cliente"
echo ""
info "Distribucion via VPN WireGuard:"
echo "  Servidor (10.13.13.4): ca-cert, server-cert, server-key"
echo "  Cliente  (10.13.13.2): ca-cert, client-cert, client-key"
echo ""
info "Test rapido de mTLS (desde Parrot OS):"
echo "  curl --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem https://10.13.13.4:8443/health"
echo ""
warn "NUNCA compartir las llaves privadas (.key.pem) por canales inseguros"
warn "Usar SCP a traves de la VPN WireGuard para transferir archivos"
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
echo "  bunker_ed25519      — Llave privada SSH"
echo "  bunker_ed25519.pub  — Llave publica SSH"
echo ""
info "Para autorizar al agente en Parrot:"
echo "  cat $SSH_DIR/bunker_ed25519.pub >> ~/.ssh/authorized_keys"
