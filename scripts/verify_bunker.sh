#!/usr/bin/env bash
# =============================================================================
# 🔒 Verificador del Búnker — Health Check de la Trinidad
# Verifica conectividad VPN, servicios, y seguridad
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

VPN_HUB="10.13.13.1"
PARROT="10.13.13.2"
AGENT="10.13.13.4"

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${CYAN}ℹ${NC} $1"; }

echo ""
echo -e "${BOLD}🛡️  Búnker DevSecOps — Health Check${NC}"
echo "════════════════════════════════════════"
echo ""

# ── 1. WireGuard Interface ───────────────────────────────────
echo -e "${BOLD}1. WireGuard Interface${NC}"

if ip link show wg0 &>/dev/null; then
    pass "Interface wg0 activa"
    WG_IP=$(ip addr show wg0 | grep "inet " | awk '{print $2}')
    info "IP asignada: $WG_IP"
else
    fail "Interface wg0 no encontrada"
    info "Ejecutar: sudo wg-quick up wg0"
fi

echo ""

# ── 2. Conectividad VPN ─────────────────────────────────────
echo -e "${BOLD}2. Conectividad VPN${NC}"

for NODE_NAME NODE_IP in "VPN Hub" "$VPN_HUB" "Parrot OS" "$PARROT" "EC2 Agent" "$AGENT"; do
    if ping -c 1 -W 2 "$NODE_IP" &>/dev/null; then
        pass "$NODE_NAME ($NODE_IP) — alcanzable"
    else
        fail "$NODE_NAME ($NODE_IP) — no responde"
    fi
done

echo ""

# ── 3. WireGuard Handshakes ─────────────────────────────────
echo -e "${BOLD}3. WireGuard Peers${NC}"

if command -v wg &>/dev/null; then
    PEERS=$(sudo wg show wg0 2>/dev/null | grep -c "peer:" || echo "0")
    info "Peers conectados: $PEERS"

    sudo wg show wg0 2>/dev/null | grep -A 3 "peer:" | while read -r line; do
        if [[ "$line" == *"latest handshake"* ]]; then
            pass "Handshake: $line"
        fi
    done
else
    fail "WireGuard tools no instalados"
fi

echo ""

# ── 4. Servicios Docker ─────────────────────────────────────
echo -e "${BOLD}4. Servicios Docker${NC}"

if command -v docker &>/dev/null; then
    RUNNING=$(docker ps --format '{{.Names}} ({{.Status}})' 2>/dev/null)
    if [ -n "$RUNNING" ]; then
        echo "$RUNNING" | while read -r container; do
            pass "$container"
        done
    else
        info "No hay containers corriendo localmente"
    fi
else
    fail "Docker no instalado"
fi

echo ""

# ── 5. Verificar que SSH NO está expuesto ────────────────────
echo -e "${BOLD}5. Seguridad SSH${NC}"

# Verificar que el puerto 22 no está en LISTEN en interfaces públicas
SSH_LISTEN=$(ss -tlnp | grep ":22 " || true)
if echo "$SSH_LISTEN" | grep -q "0.0.0.0:22"; then
    fail "SSH está escuchando en TODAS las interfaces (0.0.0.0:22)"
    info "Recomendación: Configurar ListenAddress en sshd_config"
elif echo "$SSH_LISTEN" | grep -q "10.13.13"; then
    pass "SSH solo escucha en la VPN"
else
    info "SSH status: $SSH_LISTEN"
fi

echo ""

# ── 6. Verificar mTLS certs ─────────────────────────────────
echo -e "${BOLD}6. Certificados mTLS${NC}"

CERT_DIR="./crypto/certs"
if [ -f "$CERT_DIR/ca-cert.pem" ]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_DIR/ca-cert.pem" 2>/dev/null | cut -d= -f2)
    pass "CA Root presente (expira: $EXPIRY)"
else
    info "Certificados no generados. Ejecutar: ./scripts/generate_mtls_certs.sh"
fi

if [ -f "$CERT_DIR/server-cert.pem" ]; then
    pass "Certificado del servidor presente"
fi

if [ -f "$CERT_DIR/client-cert.pem" ]; then
    pass "Certificado del cliente presente"
fi

echo ""

# ── 7. Test mTLS Connection ─────────────────────────────────
echo -e "${BOLD}7. Test mTLS (si Nginx está corriendo)${NC}"

if [ -f "$CERT_DIR/client-cert.pem" ] && [ -f "$CERT_DIR/client-key.pem" ]; then
    MTLS_RESULT=$(curl -s -o /dev/null -w "%{http_code}" \
        --cert "$CERT_DIR/client-cert.pem" \
        --key "$CERT_DIR/client-key.pem" \
        --cacert "$CERT_DIR/ca-cert.pem" \
        "https://10.13.13.4:8443/health" 2>/dev/null || echo "000")

    if [ "$MTLS_RESULT" == "200" ]; then
        pass "Conexión mTLS exitosa (HTTP $MTLS_RESULT)"
    elif [ "$MTLS_RESULT" == "000" ]; then
        info "Nginx mTLS no disponible (normal si no está configurado aún)"
    else
        fail "mTLS respondió HTTP $MTLS_RESULT"
    fi
else
    info "Certificados de cliente no encontrados"
fi

echo ""
echo "════════════════════════════════════════"
echo -e "${BOLD}Health check completado${NC}"
echo ""
