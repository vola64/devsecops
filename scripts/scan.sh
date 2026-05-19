#!/usr/bin/env bash
# =============================================================================
# scan.sh — Scan de vulnérabilités avec Trivy
# Projet CI/CD Sécurisé — DevSecOps
# =============================================================================
set -euo pipefail

# ─── Couleurs pour affichage ──────────────────────────────────────────────────
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
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH}"
OUTPUT_FORMAT="${TRIVY_FORMAT:-table}"
OUTPUT_FILE="${TRIVY_OUTPUT:-trivy-report.json}"
EXIT_CODE="${TRIVY_EXIT_CODE:-1}"

if [[ -z "$IMAGE" ]]; then
    log_error "Usage: $0 <image:tag>"
    log_error "Exemple: $0 monapp/api:latest"
    exit 1
fi

log_info "═══════════════════════════════════════════════════"
log_info " SCAN DE VULNÉRABILITÉS — Trivy"
log_info " Image    : $IMAGE"
log_info " Sévérité : $SEVERITY"
log_info "═══════════════════════════════════════════════════"

# ─── Vérification installation Trivy ─────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
    log_warn "Trivy non trouvé, installation..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
fi

# ─── Scan 1 : Vulnérabilités de l'image ──────────────────────────────────────
log_info "Scan 1/3 : Vulnérabilités OS et librairies..."
trivy image \
    --severity "$SEVERITY" \
    --format json \
    --output "$OUTPUT_FILE" \
    --exit-code "$EXIT_CODE" \
    --no-progress \
    "$IMAGE"

SCAN_EXIT=$?
if [[ $SCAN_EXIT -eq 0 ]]; then
    log_success "Aucune vulnérabilité $SEVERITY détectée dans l'image"
else
    log_error "Vulnérabilités $SEVERITY détectées ! Consulter $OUTPUT_FILE"
fi

# ─── Scan 2 : Secrets dans l'image ───────────────────────────────────────────
log_info "Scan 2/3 : Détection de secrets dans l'image..."
trivy image \
    --scanners secret \
    --format table \
    --exit-code 1 \
    --no-progress \
    "$IMAGE"

SECRET_EXIT=$?
if [[ $SECRET_EXIT -eq 0 ]]; then
    log_success "Aucun secret détecté dans l'image"
else
    log_error "Secrets détectés dans l'image ! Pipeline arrêté."
fi

# ─── Scan 3 : Mauvaises configurations ───────────────────────────────────────
log_info "Scan 3/3 : Analyse de la configuration Docker..."
trivy image \
    --scanners config \
    --format table \
    --severity "$SEVERITY" \
    --exit-code 0 \
    --no-progress \
    "$IMAGE"

log_info "═══════════════════════════════════════════════════"

# Retourner le code d'erreur le plus critique
FINAL_EXIT=$(( SCAN_EXIT | SECRET_EXIT ))
if [[ $FINAL_EXIT -eq 0 ]]; then
    log_success "Tous les scans réussis pour $IMAGE"
else
    log_error "Des problèmes ont été détectés. Voir les rapports ci-dessus."
fi

exit $FINAL_EXIT
