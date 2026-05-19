#!/usr/bin/env bash
# =============================================================================
# verify.sh — Vérification de la signature Cosign avant déploiement
# Projet CI/CD Sécurisé — DevSecOps
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Variables ────────────────────────────────────────────────────────────────
IMAGE="${1:-}"
PUB_KEY="${COSIGN_PUB_KEY:-cosign/cosign.pub}"

if [[ -z "$IMAGE" ]]; then
    log_error "Usage: $0 <image:tag>"
    log_error "Exemple: $0 docker.io/monuser/api:latest"
    exit 1
fi

log_info "═══════════════════════════════════════════════════"
log_info " VÉRIFICATION SIGNATURE — Cosign"
log_info " Image  : $IMAGE"
log_info " Clé    : $PUB_KEY"
log_info "═══════════════════════════════════════════════════"

# ─── Vérification Cosign installé ─────────────────────────────────────────────
if ! command -v cosign &>/dev/null; then
    log_error "Cosign non installé. Exécuter sign.sh d'abord ou installer Cosign."
    exit 1
fi

# ─── Vérification clé publique ────────────────────────────────────────────────
if [[ ! -f "$PUB_KEY" ]]; then
    log_error "Clé publique introuvable: $PUB_KEY"
    exit 1
fi

# ─── Vérification de la signature ────────────────────────────────────────────
log_info "Vérification de la signature cryptographique..."

VERIFY_OUTPUT=$(cosign verify \
    --key "$PUB_KEY" \
    "$IMAGE" 2>&1)

VERIFY_EXIT=$?

if [[ $VERIFY_EXIT -ne 0 ]]; then
    log_error "ÉCHEC DE VÉRIFICATION — Image non signée ou signature invalide !"
    log_error "Image refusée : $IMAGE"
    log_error "Détail : $VERIFY_OUTPUT"
    log_error ""
    log_error "⚠️  DÉPLOIEMENT BLOQUÉ — Supply chain compromise possible !"
    exit 1
fi

log_success "Signature valide pour $IMAGE"

# ─── Afficher les métadonnées de signature ────────────────────────────────────
log_info "Métadonnées de signature :"
echo "$VERIFY_OUTPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list) and data:
        payload = data[0].get('optional', {})
        print(f'  Author   : {payload.get(\"author\", \"N/A\")}')
        print(f'  Signed-at: {payload.get(\"signed-at\", \"N/A\")}')
        print(f'  Pipeline : {payload.get(\"pipeline\", \"N/A\")}')
except:
    pass
" 2>/dev/null || true

log_info "═══════════════════════════════════════════════════"
log_success "✅ Image autorisée au déploiement : $IMAGE"
