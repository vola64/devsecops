#!/usr/bin/env bash
# =============================================================================
# sign.sh — Signature d'image Docker avec Cosign
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
KEY_PATH="${COSIGN_KEY_PATH:-cosign/cosign.key}"
ANNOTATIONS_AUTHOR="${CI_COMMIT_AUTHOR:-pipeline-ci}"
ANNOTATIONS_PIPELINE="${CI_PIPELINE_URL:-local}"

if [[ -z "$IMAGE" ]]; then
    log_error "Usage: $0 <image:tag>"
    log_error "Exemple: $0 docker.io/monuser/api:latest"
    exit 1
fi

log_info "═══════════════════════════════════════════════════"
log_info " SIGNATURE — Cosign"
log_info " Image  : $IMAGE"
log_info " Clé    : $KEY_PATH"
log_info "═══════════════════════════════════════════════════"

# ─── Vérification Cosign ──────────────────────────────────────────────────────
if ! command -v cosign &>/dev/null; then
    log_warn "Cosign non trouvé, installation..."
    COSIGN_VERSION="v2.2.4"
    curl -sLO "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    chmod +x cosign-linux-amd64
    mv cosign-linux-amd64 /usr/local/bin/cosign
fi

# ─── Vérification clé privée ──────────────────────────────────────────────────
if [[ ! -f "$KEY_PATH" ]]; then
    log_error "Clé privée Cosign introuvable: $KEY_PATH"
    log_error "Générer avec: cosign generate-key-pair --output-key-prefix cosign/cosign"
    exit 1
fi

# ─── Signature de l'image ─────────────────────────────────────────────────────
log_info "Signature de l'image en cours..."

cosign sign \
    --key "$KEY_PATH" \
    --yes \
    --annotations "author=${ANNOTATIONS_AUTHOR}" \
    --annotations "pipeline=${ANNOTATIONS_PIPELINE}" \
    --annotations "signed-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "$IMAGE"

log_success "Image signée avec succès : $IMAGE"

# ─── Vérification immédiate après signature ───────────────────────────────────
log_info "Vérification de la signature..."
PUB_KEY="${KEY_PATH%.key}.pub"
if [[ -f "$PUB_KEY" ]]; then
    cosign verify \
        --key "$PUB_KEY" \
        "$IMAGE" \
        | jq '.[0].optional // .[0]' 2>/dev/null || true
    log_success "Signature vérifiée avec succès"
else
    log_warn "Clé publique introuvable ($PUB_KEY), vérification ignorée"
fi

log_info "═══════════════════════════════════════════════════"
log_success "Signature terminée pour $IMAGE"
