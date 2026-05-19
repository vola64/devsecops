// =============================================================================
// Jenkinsfile — Pipeline CI/CD Sécurisé DevSecOps
// Projet : Supply Chain Security — Jenkins + Docker Hub
// =============================================================================
//
// CREDENTIALS JENKINS REQUIS (Manage Jenkins → Credentials) :
//   docker-hub-credentials  → Username/Password (Docker Hub)
//   cosign-private-key      → Secret File (cosign.key)
//   cosign-public-key       → Secret File (cosign.pub)
//   cosign-password         → Secret Text (passphrase Cosign)
//   deploy-ssh-key          → SSH Username with Private Key (optionnel)
// =============================================================================

pipeline {

    // ─── Agent ────────────────────────────────────────────────────────────────
    agent {
        docker {
            image 'docker:26.1-dind'
            args  '--privileged -v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    // ─── Variables globales ───────────────────────────────────────────────────
    environment {
        DOCKER_REGISTRY  = 'docker.io'
        IMAGE_NAME       = "devsecops-api"
        IMAGE_TAG        = "${env.GIT_COMMIT?.take(8) ?: 'latest'}"
        IMAGE_FULL       = "${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
        IMAGE_LATEST     = "${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:latest"
        TRIVY_SEVERITY   = 'CRITICAL,HIGH'
        REPORTS_DIR      = 'reports'
    }

    // ─── Options globales ─────────────────────────────────────────────────────
    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')
    }

    // ─── Déclencheurs ─────────────────────────────────────────────────────────
    triggers {
        pollSCM('H/5 * * * *')   // Vérifier GitLab toutes les 5 min
    }

    // =========================================================================
    // STAGES
    // =========================================================================
    stages {

        // ─── Stage 0 : Initialisation ─────────────────────────────────────────
        stage('🔧 Init') {
            steps {
                echo '═══════════════════════════════════════════════'
                echo " Pipeline DevSecOps — Build #${env.BUILD_NUMBER}"
                echo " Commit  : ${env.GIT_COMMIT?.take(12)}"
                echo " Branche : ${env.GIT_BRANCH}"
                echo " Image   : ${env.IMAGE_FULL}"
                echo '═══════════════════════════════════════════════'
                sh 'mkdir -p ${REPORTS_DIR}'
                sh 'docker info'
            }
        }

        // =========================================================================
        // STAGE 1 — SAST : Analyse statique + Secrets
        // =========================================================================
        stage('🔍 SAST & Secrets') {
            parallel {

                // ─── Bandit : SAST Python ─────────────────────────────────────
                stage('Bandit') {
                    agent {
                        docker {
                            image 'python:3.11-slim'
                            reuseNode true
                        }
                    }
                    steps {
                        echo '🔍 Analyse SAST Python avec Bandit...'
                        sh '''
                            pip install bandit --quiet
                            bandit -r src/ \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                -ll \
                                --severity-level medium \
                                || true
                            bandit -r src/ -f txt -ll --severity-level medium
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/bandit-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }

                // ─── Gitleaks : Secrets dans le code ──────────────────────────
                stage('Gitleaks') {
                    agent {
                        docker {
                            image 'zricethezav/gitleaks:v8.18.4'
                            reuseNode true
                            args '--entrypoint='
                        }
                    }
                    steps {
                        echo '🔐 Détection de secrets avec Gitleaks...'
                        sh '''
                            gitleaks detect \
                                --source . \
                                --report-format json \
                                --report-path ${REPORTS_DIR}/gitleaks-report.json \
                                --no-git \
                                --verbose
                        '''
                    }
                    post {
                        failure {
                            error '❌ GITLEAKS : Secrets détectés dans le code ! Pipeline arrêté.'
                        }
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/gitleaks-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }

                // ─── Semgrep : SAST multi-règles OWASP ────────────────────────
                stage('Semgrep') {
                    agent {
                        docker {
                            image 'returntocorp/semgrep:1.72.0'
                            reuseNode true
                        }
                    }
                    steps {
                        echo '🔍 Analyse SAST OWASP avec Semgrep...'
                        sh '''
                            semgrep scan \
                                --config=p/python \
                                --config=p/security-audit \
                                --config=p/owasp-top-ten \
                                --json \
                                --output ${REPORTS_DIR}/semgrep-report.json \
                                src/ || true
                            semgrep scan \
                                --config=p/python \
                                --config=p/security-audit \
                                src/
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/semgrep-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }
            }
            post {
                success { echo '✅ SAST — Aucun problème critique détecté' }
                failure { echo '❌ SAST — Des problèmes de sécurité ont été détectés' }
            }
        }

        // =========================================================================
        // STAGE 2 — BUILD : Construction de l'image Docker
        // =========================================================================
        stage('🐳 Build') {
            steps {
                echo '🐳 Construction de l\'image Docker sécurisée...'
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-credentials',
                    usernameVariable: 'DOCKER_HUB_USER',
                    passwordVariable: 'DOCKER_HUB_PASS'
                )]) {
                    sh '''
                        # Login Docker Hub
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} \
                            -u "$DOCKER_HUB_USER" --password-stdin

                        # Variables dynamiques
                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
                        IMAGE_LATEST="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:latest"
                        CREATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

                        # Build multi-stage avec labels OCI
                        DOCKER_BUILDKIT=1 docker build \
                            --file docker/Dockerfile \
                            --tag "$IMAGE_FULL" \
                            --tag "$IMAGE_LATEST" \
                            --label "org.opencontainers.image.created=${CREATED_AT}" \
                            --label "org.opencontainers.image.revision=${GIT_COMMIT}" \
                            --label "org.opencontainers.image.version=${IMAGE_TAG}" \
                            --label "org.opencontainers.image.source=${GIT_URL}" \
                            --label "org.opencontainers.image.ref.name=${GIT_BRANCH}" \
                            --build-arg BUILDKIT_INLINE_CACHE=1 \
                            .

                        echo "✅ Image construite: $IMAGE_FULL"
                        docker images "${DOCKER_HUB_USER}/${IMAGE_NAME}"

                        # Sauvegarder pour les stages suivants
                        docker save "$IMAGE_FULL" | gzip > image.tar.gz
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo '✅ Build Docker réussi' }
                failure { error '❌ Build Docker échoué' }
            }
        }

        // =========================================================================
        // STAGE 3 — TEST : Tests unitaires et couverture
        // =========================================================================
        stage('🧪 Tests') {
            agent {
                docker {
                    image 'python:3.11-slim'
                    reuseNode true
                }
            }
            steps {
                echo '🧪 Exécution des tests unitaires...'
                sh '''
                    pip install -r requirements.txt --quiet
                    python -m pytest tests/ \
                        --cov=src \
                        --cov-report=html:${REPORTS_DIR}/coverage-html \
                        --cov-report=xml:${REPORTS_DIR}/coverage.xml \
                        --cov-report=term-missing \
                        --cov-fail-under=70 \
                        --junit-xml=${REPORTS_DIR}/pytest-report.xml \
                        -v
                '''
            }
            post {
                always {
                    // Publier les résultats JUnit
                    junit testResults: "${REPORTS_DIR}/pytest-report.xml",
                          allowEmptyResults: true

                    // Publier le rapport de couverture HTML
                    publishHTML(target: [
                        allowMissing         : false,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : "${REPORTS_DIR}/coverage-html",
                        reportFiles          : 'index.html',
                        reportName           : '📊 Coverage Report'
                    ])

                    archiveArtifacts artifacts: "${REPORTS_DIR}/coverage.xml",
                                     allowEmptyArchive: true
                }
                success { echo '✅ Tests réussis — Couverture ≥ 70%' }
                failure { error '❌ Tests échoués ou couverture insuffisante' }
            }
        }

        // =========================================================================
        // STAGE 4 — SCAN : Vulnérabilités image + dépendances
        // =========================================================================
        stage('🔎 Scan Sécurité') {
            parallel {

                // ─── Trivy : Scan image Docker ─────────────────────────────────
                stage('Trivy') {
                    agent {
                        docker {
                            image 'aquasec/trivy:0.51.4'
                            reuseNode true
                            args '--entrypoint= -v /var/run/docker.sock:/var/run/docker.sock'
                        }
                    }
                    steps {
                        echo '🔍 Scan Trivy de l\'image Docker...'
                        sh '''
                            # Charger l'image sauvegardée
                            docker load < image.tar.gz

                            # Scan vulnérabilités
                            trivy image \
                                --severity ${TRIVY_SEVERITY} \
                                --format json \
                                --output ${REPORTS_DIR}/trivy-vuln-report.json \
                                --exit-code 1 \
                                --no-progress \
                                $(docker images --format "{{.Repository}}:{{.Tag}}" | head -1)

                            # Scan secrets dans l'image
                            trivy image \
                                --scanners secret \
                                --format json \
                                --output ${REPORTS_DIR}/trivy-secret-report.json \
                                --exit-code 1 \
                                --no-progress \
                                $(docker images --format "{{.Repository}}:{{.Tag}}" | head -1)
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/trivy-*.json",
                                             allowEmptyArchive: true
                        }
                        success { echo '✅ Trivy — Aucune vulnérabilité CRITICAL/HIGH' }
                        failure { error '❌ Trivy — Vulnérabilités critiques détectées !' }
                    }
                }

                // ─── OWASP Dependency Check ────────────────────────────────────
                stage('OWASP DC') {
                    agent {
                        docker {
                            image 'owasp/dependency-check:latest'
                            reuseNode true
                        }
                    }
                    steps {
                        echo '🔍 OWASP Dependency Check...'
                        sh '''
                            /usr/share/dependency-check/bin/dependency-check.sh \
                                --project "DevSecOps API" \
                                --scan . \
                                --format JSON \
                                --format HTML \
                                --out ${REPORTS_DIR}/ \
                                --failOnCVSS 7 \
                                --enableRetired || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/dependency-check-report.*",
                                             allowEmptyArchive: true
                            publishHTML(target: [
                                allowMissing         : true,
                                alwaysLinkToLastBuild: true,
                                keepAll              : true,
                                reportDir            : REPORTS_DIR,
                                reportFiles          : 'dependency-check-report.html',
                                reportName           : '🛡️ OWASP Report'
                            ])
                        }
                    }
                }
            }
        }

        // =========================================================================
        // STAGE 5 — SIGN : Signature cryptographique avec Cosign
        // =========================================================================
        stage('✍️ Signature Cosign') {
            steps {
                echo '✍️ Signature de l\'image avec Cosign...'
                withCredentials([
                    usernamePassword(
                        credentialsId: 'docker-hub-credentials',
                        usernameVariable: 'DOCKER_HUB_USER',
                        passwordVariable: 'DOCKER_HUB_PASS'
                    ),
                    file(credentialsId: 'cosign-private-key', variable: 'COSIGN_KEY_FILE'),
                    file(credentialsId: 'cosign-public-key',  variable: 'COSIGN_PUB_FILE'),
                    string(credentialsId: 'cosign-password',  variable: 'COSIGN_PASSWORD')
                ]) {
                    sh '''
                        # Installer Cosign
                        COSIGN_VERSION="v2.2.4"
                        curl -sLO "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
                        chmod +x cosign-linux-amd64 && mv cosign-linux-amd64 /usr/local/bin/cosign
                        cosign version

                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"

                        # Login et push de l'image d'abord
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} \
                            -u "$DOCKER_HUB_USER" --password-stdin
                        docker push "$IMAGE_FULL"

                        # Signer l'image
                        COSIGN_PASSWORD="$COSIGN_PASSWORD" cosign sign \
                            --key "$COSIGN_KEY_FILE" \
                            --yes \
                            --annotations "pipeline=${BUILD_URL}" \
                            --annotations "author=${GIT_AUTHOR_NAME}" \
                            --annotations "commit=${GIT_COMMIT}" \
                            --annotations "branch=${GIT_BRANCH}" \
                            --annotations "signed-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                            "$IMAGE_FULL"

                        # Vérification immédiate
                        echo "🔍 Vérification de la signature..."
                        cosign verify --key "$COSIGN_PUB_FILE" "$IMAGE_FULL"

                        echo "✅ Signature Cosign valide pour $IMAGE_FULL"
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo '✅ Image signée et vérifiée avec succès' }
                failure { error '❌ Échec de la signature Cosign — Pipeline arrêté' }
            }
        }

        // =========================================================================
        // STAGE 6 — PUSH : Push Docker Hub (image signée)
        // =========================================================================
        stage('📦 Push Docker Hub') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    buildingTag()
                }
            }
            steps {
                echo '📦 Push de l\'image vers Docker Hub...'
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-credentials',
                    usernameVariable: 'DOCKER_HUB_USER',
                    passwordVariable: 'DOCKER_HUB_PASS'
                )]) {
                    sh '''
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} \
                            -u "$DOCKER_HUB_USER" --password-stdin

                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
                        IMAGE_LATEST="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:latest"
                        BRANCH_TAG=$(echo ${GIT_BRANCH} | sed 's|/|-|g')
                        IMAGE_BRANCH="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${BRANCH_TAG}"

                        docker tag "$IMAGE_FULL" "$IMAGE_BRANCH"
                        docker push "$IMAGE_BRANCH"
                        docker push "$IMAGE_LATEST"

                        echo "✅ Images disponibles sur Docker Hub:"
                        echo "   $IMAGE_FULL"
                        echo "   $IMAGE_LATEST"
                        echo "   $IMAGE_BRANCH"
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo '✅ Push Docker Hub réussi' }
            }
        }

        // =========================================================================
        // STAGE 7 — DEPLOY : Déploiement Docker Compose sécurisé
        // =========================================================================
        stage('🚀 Déploiement') {
            when {
                branch 'main'
            }
            // Déploiement manuel (approbation requise)
            input {
                message '🚀 Déployer en production ?'
                ok      'Oui, déployer !'
                parameters {
                    string(name: 'DEPLOY_ENV', defaultValue: 'production',
                           description: 'Environnement cible')
                }
            }
            steps {
                echo "🚀 Déploiement vers ${DEPLOY_ENV}..."
                withCredentials([
                    usernamePassword(
                        credentialsId: 'docker-hub-credentials',
                        usernameVariable: 'DOCKER_HUB_USER',
                        passwordVariable: 'DOCKER_HUB_PASS'
                    ),
                    file(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUB_FILE')
                ]) {
                    sh '''
                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"

                        # ─── Vérifier la signature AVANT déploiement ─────────
                        echo "🔍 Vérification signature avant déploiement..."
                        if command -v cosign &>/dev/null; then
                            cosign verify --key "$COSIGN_PUB_FILE" "$IMAGE_FULL"
                            echo "✅ Signature valide — déploiement autorisé"
                        else
                            echo "⚠️  Cosign non disponible, vérification ignorée"
                        fi

                        # ─── Déploiement Docker Compose ───────────────────────
                        export DOCKER_IMAGE="$IMAGE_FULL"
                        export APP_VERSION="${IMAGE_TAG}"

                        docker compose pull api
                        docker compose up -d --no-deps api

                        sleep 10

                        # ─── Health check post-déploiement ────────────────────
                        echo "🏥 Health check..."
                        curl -sf http://localhost:8000/health || exit 1
                        echo "✅ Application healthy après déploiement"

                        docker compose ps
                    '''
                }
            }
            post {
                success {
                    echo '✅ Déploiement réussi en production'
                    slackSend(
                        color: 'good',
                        message: "✅ *DevSecOps API* déployée — Build #${env.BUILD_NUMBER} | ${env.IMAGE_FULL}"
                    )
                }
                failure {
                    echo '❌ Déploiement échoué — Rollback recommandé'
                    slackSend(
                        color: 'danger',
                        message: "❌ *DevSecOps API* — Échec déploiement Build #${env.BUILD_NUMBER}"
                    )
                }
            }
        }

    }  // end stages

    // =========================================================================
    // POST : Actions globales
    // =========================================================================
    post {

        always {
            echo '📊 Génération du rapport de sécurité consolidé...'
            sh '''
                python3 << 'PYEOF'
import json, os
from datetime import datetime

print("=" * 60)
print("  RAPPORT DE SÉCURITÉ — Pipeline Jenkins DevSecOps")
print(f"  Build     : #{os.getenv('BUILD_NUMBER', 'N/A')}")
print(f"  Commit    : {os.getenv('GIT_COMMIT', 'N/A')[:12]}")
print(f"  Date      : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
print("=" * 60)

reports_dir = os.getenv('REPORTS_DIR', 'reports')

# Bandit
try:
    with open(f"{reports_dir}/bandit-report.json") as f:
        b = json.load(f)
    issues = b.get("results", [])
    highs  = [i for i in issues if i.get("issue_severity") in ("HIGH", "MEDIUM")]
    print(f"\\n🔍 BANDIT    | Total: {len(issues)} | MEDIUM+: {len(highs)}")
except:
    print("\\n🔍 BANDIT    | rapport non disponible")

# Trivy
try:
    with open(f"{reports_dir}/trivy-vuln-report.json") as f:
        t = json.load(f)
    vulns = []
    for result in t.get("Results", []):
        vulns.extend(result.get("Vulnerabilities", []) or [])
    crits = [v for v in vulns if v.get("Severity") == "CRITICAL"]
    highs = [v for v in vulns if v.get("Severity") == "HIGH"]
    print(f"🐳 TRIVY     | CRITICAL: {len(crits)} | HIGH: {len(highs)}")
except:
    print("🐳 TRIVY     | rapport non disponible")

print("\\n" + "=" * 60)
PYEOF
            ''' 
            // Archiver tous les rapports
            archiveArtifacts artifacts: 'reports/**/*',
                             allowEmptyArchive: true

            // Nettoyer les images Docker locales
            sh 'docker rmi $(docker images -q) --force 2>/dev/null || true'
            sh 'rm -f image.tar.gz'

            // Nettoyer le workspace (optionnel)
            cleanWs()
        }

        success {
            echo "✅ Pipeline DevSecOps réussi — Build #${env.BUILD_NUMBER}"
        }

        failure {
            echo "❌ Pipeline DevSecOps échoué — Build #${env.BUILD_NUMBER}"
            emailext(
                subject: "❌ Pipeline DevSecOps FAILED — Build #${env.BUILD_NUMBER}",
                body: """
                    Le pipeline CI/CD a échoué.
                    Build     : #${env.BUILD_NUMBER}
                    Commit    : ${env.GIT_COMMIT}
                    Branche   : ${env.GIT_BRANCH}
                    Détails   : ${env.BUILD_URL}
                """,
                recipientProviders: [[$class: 'DevelopersRecipientProvider']]
            )
        }

        unstable {
            echo "⚠️ Pipeline instable — Vérifier les tests"
        }
    }

}  // end pipeline
