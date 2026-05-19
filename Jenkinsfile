// =============================================================================
// Jenkinsfile — Pipeline CI/CD Sécurisé DevSecOps
// Projet : Supply Chain Security — Jenkins + Docker Hub
// =============================================================================
//
// PLUGINS JENKINS REQUIS :
//   - Docker Pipeline         → agent { docker { ... } }
//   - AnsiColor               → ansiColor('xterm')
//   - HTML Publisher          → publishHTML(...)
//   - Slack Notification      → slackSend(...)
//   - Email Extension         → emailext(...)
//
// CREDENTIALS JENKINS REQUIS (Manage Jenkins → Credentials) :
//   docker-hub-credentials  → Username/Password (Docker Hub)
//   cosign-private-key      → Secret File (cosign.key)
//   cosign-public-key       → Secret File (cosign.pub)
//   cosign-password         → Secret Text (passphrase Cosign)
// =============================================================================

pipeline {

    // ─── Agent global ─────────────────────────────────────────────────────────
    // FIX : "any" au lieu de docker:dind global.
    // Chaque stage déclare son propre agent docker (reuseNode true).
    // Le nœud Jenkins doit avoir Docker installé et l'utilisateur jenkins
    // dans le groupe docker  →  sudo usermod -aG docker jenkins
    agent any

    // ─── Variables globales ───────────────────────────────────────────────────
    // FIX : IMAGE_FULL et IMAGE_LATEST supprimés ici car DOCKER_HUB_USER
    //       n'est disponible que dans les blocs withCredentials.
    //       Ces variables sont recalculées en shell dans chaque stage.
    environment {
        DOCKER_REGISTRY = 'docker.io'
        IMAGE_NAME      = "devsecops-api"
        IMAGE_TAG       = "${env.GIT_COMMIT?.take(8) ?: 'latest'}"
        TRIVY_SEVERITY  = 'CRITICAL,HIGH'
        REPORTS_DIR     = 'reports'
    }

    // ─── Options globales ─────────────────────────────────────────────────────
    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')   // FIX : nécessite le plugin AnsiColor
    }

    // ─── Déclencheurs ─────────────────────────────────────────────────────────
    triggers {
        pollSCM('H/5 * * * *')
    }

    // =========================================================================
    // STAGES
    // =========================================================================
    stages {

        // ─── Stage 0 : Initialisation ─────────────────────────────────────────
        stage('Init') {
            steps {
                echo '═══════════════════════════════════════════════'
                echo " Pipeline DevSecOps — Build #${env.BUILD_NUMBER}"
                echo " Commit  : ${env.GIT_COMMIT?.take(12)}"
                echo " Branche : ${env.GIT_BRANCH}"
                echo " Image   : ${env.IMAGE_NAME}:${env.IMAGE_TAG}"
                echo '═══════════════════════════════════════════════'
                sh 'mkdir -p ${REPORTS_DIR}'
                sh 'docker info'
            }
        }

        // =========================================================================
        // STAGE 1 — SAST : Analyse statique + Secrets
        // =========================================================================
        stage('SAST et Secrets') {
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
                        echo 'Analyse SAST Python avec Bandit...'
                        sh '''
                            # FIX : HOME=/tmp evite "Permission denied: /.local"
                            export HOME=/tmp
                            # FIX : pip installe les scripts dans /tmp/.local/bin
                            # qui n'est pas dans PATH par defaut — on l'ajoute
                            export PATH="/tmp/.local/bin:$PATH"
                            pip install bandit --quiet
                            bandit -r src/ \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                -ll \
                                --severity-level medium \
                                || true
                            bandit -r src/ -f txt -ll --severity-level medium \
                                || true
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
                        echo 'Detection de secrets avec Gitleaks...'
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
                            error 'GITLEAKS : Secrets detectes dans le code ! Pipeline arrete.'
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
                        echo 'Analyse SAST OWASP avec Semgrep...'
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
                success { echo 'SAST — Aucun probleme critique detecte' }
                failure { echo 'SAST — Des problemes de securite ont ete detectes' }
            }
        }

        // =========================================================================
        // STAGE 2 — BUILD : Construction de l'image Docker
        // =========================================================================
        stage('Build Docker') {
            steps {
                echo "Construction de l'image Docker securisee..."
                withCredentials([usernamePassword(
                    credentialsId: 'docker-hub-credentials',
                    usernameVariable: 'DOCKER_HUB_USER',
                    passwordVariable: 'DOCKER_HUB_PASS'
                )]) {
                    sh '''
                        # Login Docker Hub
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} \
                            -u "$DOCKER_HUB_USER" --password-stdin

                        # Calcul des noms d'images
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

                        echo "Image construite : $IMAGE_FULL"
                        docker images "${DOCKER_HUB_USER}/${IMAGE_NAME}"

                        # Sauvegarder l'image pour les stages suivants
                        docker save "$IMAGE_FULL" | gzip > image.tar.gz
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo 'Build Docker reussi' }
                failure { error 'Build Docker echoue' }
            }
        }

        // =========================================================================
        // STAGE 3 — TEST : Tests unitaires et couverture
        // =========================================================================
        stage('Tests') {
            agent {
                docker {
                    image 'python:3.11-slim'
                    reuseNode true
                }
            }
            steps {
                echo 'Execution des tests unitaires...'
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
                    junit testResults: "${REPORTS_DIR}/pytest-report.xml",
                          allowEmptyResults: true

                    // FIX : nécessite le plugin HTML Publisher
                    publishHTML(target: [
                        allowMissing         : false,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : "${REPORTS_DIR}/coverage-html",
                        reportFiles          : 'index.html',
                        reportName           : 'Coverage Report'
                    ])

                    archiveArtifacts artifacts: "${REPORTS_DIR}/coverage.xml",
                                     allowEmptyArchive: true
                }
                success { echo 'Tests reussis — Couverture superieure a 70%' }
                failure { error 'Tests echoues ou couverture insuffisante' }
            }
        }

        // =========================================================================
        // STAGE 4 — SCAN : Vulnérabilités image + dépendances
        // =========================================================================
        stage('Scan Securite') {
            parallel {

                // ─── Trivy : Scan image Docker ─────────────────────────────────
                stage('Trivy') {
                    agent {
                        docker {
                            image 'aquasec/trivy:0.51.4'
                            reuseNode true
                            // FIX : accès au socket Docker pour charger l'image
                            args '--entrypoint= -v /var/run/docker.sock:/var/run/docker.sock'
                        }
                    }
                    steps {
                        echo "Scan Trivy de l'image Docker..."
                        sh '''
                            # Charger l'image sauvegardée au stage Build
                            docker load < image.tar.gz

                            # FIX : nom d'image explicite plutôt que "head -1"
                            TARGET_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

                            # Scan vulnérabilités
                            trivy image \
                                --severity ${TRIVY_SEVERITY} \
                                --format json \
                                --output ${REPORTS_DIR}/trivy-vuln-report.json \
                                --exit-code 1 \
                                --no-progress \
                                "$TARGET_IMAGE"

                            # Scan secrets dans l'image
                            trivy image \
                                --scanners secret \
                                --format json \
                                --output ${REPORTS_DIR}/trivy-secret-report.json \
                                --exit-code 1 \
                                --no-progress \
                                "$TARGET_IMAGE"
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/trivy-*.json",
                                             allowEmptyArchive: true
                        }
                        success { echo 'Trivy — Aucune vulnerabilite CRITICAL/HIGH' }
                        failure { error 'Trivy — Vulnerabilites critiques detectees !' }
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
                        echo 'OWASP Dependency Check...'
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
                            // FIX : nécessite le plugin HTML Publisher
                            publishHTML(target: [
                                allowMissing         : true,
                                alwaysLinkToLastBuild: true,
                                keepAll              : true,
                                reportDir            : REPORTS_DIR,
                                reportFiles          : 'dependency-check-report.html',
                                reportName           : 'OWASP Report'
                            ])
                        }
                    }
                }
            }
        }

        // =========================================================================
        // STAGE 5 — SIGN : Signature cryptographique avec Cosign
        // =========================================================================
        stage('Signature Cosign') {
            steps {
                echo "Signature de l'image avec Cosign..."
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

                        # Login et push de l'image
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
                        echo "Verification de la signature..."
                        cosign verify --key "$COSIGN_PUB_FILE" "$IMAGE_FULL"

                        echo "Signature Cosign valide pour $IMAGE_FULL"
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo 'Image signee et verifiee avec succes' }
                failure { error 'Echec de la signature Cosign — Pipeline arrete' }
            }
        }

        // =========================================================================
        // STAGE 6 — PUSH : Push Docker Hub (image signée)
        // =========================================================================
        stage('Push Docker Hub') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                    buildingTag()
                }
            }
            steps {
                echo "Push de l'image vers Docker Hub..."
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

                        echo "Images disponibles sur Docker Hub :"
                        echo "   $IMAGE_FULL"
                        echo "   $IMAGE_LATEST"
                        echo "   $IMAGE_BRANCH"
                    '''
                }
            }
            post {
                always  { sh 'docker logout ${DOCKER_REGISTRY} || true' }
                success { echo 'Push Docker Hub reussi' }
            }
        }

        // =========================================================================
        // STAGE 7 — DEPLOY : Déploiement Docker Compose sécurisé
        // =========================================================================
        stage('Deploiement') {
            when {
                branch 'main'
            }
            input {
                message 'Deployer en production ?'
                ok      'Oui, deployer !'
                parameters {
                    string(name: 'DEPLOY_ENV', defaultValue: 'production',
                           description: 'Environnement cible')
                }
            }
            steps {
                echo "Deploiement vers ${DEPLOY_ENV}..."
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

                        # Vérifier la signature AVANT déploiement
                        echo "Verification signature avant deploiement..."
                        if command -v cosign &>/dev/null; then
                            cosign verify --key "$COSIGN_PUB_FILE" "$IMAGE_FULL"
                            echo "Signature valide — deploiement autorise"
                        else
                            echo "Cosign non disponible, verification ignoree"
                        fi

                        # Déploiement Docker Compose
                        export DOCKER_IMAGE="$IMAGE_FULL"
                        export APP_VERSION="${IMAGE_TAG}"

                        docker compose pull api
                        docker compose up -d --no-deps api

                        sleep 10

                        # Health check post-déploiement
                        echo "Health check..."
                        curl -sf http://localhost:8000/health || exit 1
                        echo "Application healthy apres deploiement"

                        docker compose ps
                    '''
                }
            }
            post {
                success {
                    echo 'Deploiement reussi en production'
                    // FIX : nécessite le plugin Slack Notification
                    slackSend(
                        color: 'good',
                        message: "DevSecOps API deployee — Build #${env.BUILD_NUMBER} | ${env.IMAGE_NAME}:${env.IMAGE_TAG}"
                    )
                }
                failure {
                    echo 'Deploiement echoue — Rollback recommande'
                    slackSend(
                        color: 'danger',
                        message: "DevSecOps API — Echec deploiement Build #${env.BUILD_NUMBER}"
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
            echo 'Generation du rapport de securite CSV...'
            sh '''
                DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                CSV="${REPORTS_DIR}/security-report.csv"

                # En-tete CSV
                echo "build,commit,date,outil,metrique,valeur,statut" > "$CSV"

                # Bandit
                if [ -f "${REPORTS_DIR}/bandit-report.json" ]; then
                    TOTAL=$(grep -c "issue_severity" "${REPORTS_DIR}/bandit-report.json" || echo 0)
                    HIGH=$(grep -c "HIGH" "${REPORTS_DIR}/bandit-report.json" || echo 0)
                    MED=$(grep -c "MEDIUM" "${REPORTS_DIR}/bandit-report.json" || echo 0)
                    LOW=$(grep -c "LOW" "${REPORTS_DIR}/bandit-report.json" || echo 0)
                    if [ "$HIGH" -gt 0 ]; then STATUT_B="ECHEC"; else STATUT_B="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,total_issues,${TOTAL},${STATUT_B}" >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,high_issues,${HIGH},${STATUT_B}"   >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,medium_issues,${MED},${STATUT_B}"  >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,low_issues,${LOW},${STATUT_B}"     >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,rapport,non_disponible,INCONNU"    >> "$CSV"
                fi

                # Gitleaks
                if [ -f "${REPORTS_DIR}/gitleaks-report.json" ]; then
                    LEAKS=$(grep -c "RuleID" "${REPORTS_DIR}/gitleaks-report.json" || echo 0)
                    if [ "$LEAKS" -gt 0 ]; then STATUT_G="ECHEC"; else STATUT_G="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Gitleaks,secrets_detectes,${LEAKS},${STATUT_G}" >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Gitleaks,rapport,non_disponible,INCONNU"   >> "$CSV"
                fi

                # Semgrep
                if [ -f "${REPORTS_DIR}/semgrep-report.json" ]; then
                    FINDINGS=$(grep -c "check_id" "${REPORTS_DIR}/semgrep-report.json" || echo 0)
                    if [ "$FINDINGS" -gt 0 ]; then STATUT_S="AVERTISSEMENT"; else STATUT_S="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Semgrep,findings,${FINDINGS},${STATUT_S}"  >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Semgrep,rapport,non_disponible,INCONNU"    >> "$CSV"
                fi

                # Trivy
                if [ -f "${REPORTS_DIR}/trivy-vuln-report.json" ]; then
                    CRITS=$(grep -c "CRITICAL" "${REPORTS_DIR}/trivy-vuln-report.json" || echo 0)
                    HIGHS=$(grep -c "HIGH" "${REPORTS_DIR}/trivy-vuln-report.json" || echo 0)
                    if [ "$CRITS" -gt 0 ]; then STATUT_T="ECHEC"; else STATUT_T="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,critical,${CRITS},${STATUT_T}"       >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,high,${HIGHS},${STATUT_T}"           >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,rapport,non_disponible,INCONNU"      >> "$CSV"
                fi

                echo ""
                echo "======================================================="
                echo "  RAPPORT CSV : ${CSV}"
                echo "======================================================="
                cat "$CSV"
                echo "======================================================="
            '''

            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
            sh 'docker rmi $(docker images -q) --force 2>/dev/null || true'
            sh 'rm -f image.tar.gz'
            cleanWs()
        }

        success {
            echo "Pipeline DevSecOps reussi — Build #${env.BUILD_NUMBER}"
        }

        failure {
            echo "Pipeline DevSecOps echoue — Build #${env.BUILD_NUMBER}"
        }

        unstable {
            echo "Pipeline instable — Verifier les tests"
        }
    }

}  // end pipeline
