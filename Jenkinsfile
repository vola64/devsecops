// =============================================================================
// Jenkinsfile — Pipeline CI/CD Sécurisé DevSecOps
// Fix: agent any, pip install bandit+semgrep, timeout 60min
// =============================================================================

pipeline {

    agent any

    environment {
        DOCKER_REGISTRY = 'docker.io'
        IMAGE_NAME      = "devsecops-api"
        IMAGE_TAG       = "${env.GIT_COMMIT?.take(8) ?: 'latest'}"
        TRIVY_SEVERITY  = 'CRITICAL,HIGH'
        REPORTS_DIR     = 'reports'
        // Paramètres pour stabiliser pip et curl
        PIP_TIMEOUT     = '60'
        PIP_RETRIES     = '5'
    }

    options {
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        ansiColor('xterm')
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

    stages {

        stage('Init') {
            steps {
                echo '═══════════════════════════════════════════════'
                echo " Pipeline DevSecOps — Build #${env.BUILD_NUMBER}"
                echo '═══════════════════════════════════════════════'
                sh 'mkdir -p ${REPORTS_DIR}'
                sh 'docker info'
            }
        }

        // =========================================================================
        // STAGE 1 — SAST : Bandit + Semgrep (pip) + Gitleaks (parallel)
        // FIX: Bandit et Semgrep installés via pip dans python:3.11-slim
        //      (évite pipelinecomponents/bandit inexistant et semgrep ~2GB)
        // =========================================================================
        stage('SAST et Secrets') {
            parallel {

                // ── Bandit + Semgrep via pip (image légère python:3.11-slim) ──
                stage('Bandit + Semgrep') {
                    options { retry(3) }
                    agent {
                        docker {
                            image 'python:3.11-slim'
                            reuseNode true
                            args '-u root'  // FIX: permission denied /.local
                        }
                    }
                    steps {
                        echo 'Installation et analyse SAST (Bandit + Semgrep)...'
                        sh '''
                            pip install bandit semgrep --quiet \
                                --default-timeout=60 --retries 5

                            echo "--- Bandit SAST ---"
                            bandit -r src/ \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                -ll --severity-level medium || true
                            bandit -r src/ -ll --severity-level medium

                            echo "--- Semgrep OWASP ---"
                            semgrep scan \
                                --config=p/python \
                                --config=p/security-audit \
                                --json \
                                --output ${REPORTS_DIR}/semgrep-report.json \
                                src/ || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/bandit-report.json", allowEmptyArchive: true
                            archiveArtifacts artifacts: "${REPORTS_DIR}/semgrep-report.json", allowEmptyArchive: true
                        }
                    }
                }

                // ── Gitleaks : détection secrets (image légère, déjà prouvée) ──
                stage('Gitleaks') {
                    options { retry(3) }
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
                        failure { error 'GITLEAKS : Secrets detectes dans le code !' }
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/gitleaks-report.json", allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        stage('Build Docker') {
            steps {
                echo "Construction de l'image Docker..."
                withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'DOCKER_HUB_USER', passwordVariable: 'DOCKER_HUB_PASS')]) {
                    sh '''
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} -u "$DOCKER_HUB_USER" --password-stdin
                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
                        DOCKER_BUILDKIT=1 docker build --file docker/Dockerfile --tag "$IMAGE_FULL" --tag "${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:latest" .
                        docker save "$IMAGE_FULL" | gzip > image.tar.gz
                    '''
                }
            }
        }

        stage('Tests') {
            options { retry(3) }
            agent {
                docker {
                    image 'python:3.11-slim'
                    reuseNode true
                    args '-u root'  // FIX: permission denied /.local
                }
            }
            steps {
                echo 'Execution des tests unitaires (avec options de retry)...'
                sh '''
                    # CORRECTION : Ajout de timeout et retries pour stabiliser pip
                    pip install --default-timeout=${PIP_TIMEOUT} --retries ${PIP_RETRIES} -r requirements.txt --quiet
                    python -m pytest tests/ --cov=src --cov-report=xml:${REPORTS_DIR}/coverage.xml --cov-fail-under=70 --junit-xml=${REPORTS_DIR}/pytest-report.xml -v
                '''
            }
            post {
                always {
                    junit testResults: "${REPORTS_DIR}/pytest-report.xml", allowEmptyResults: true
                    archiveArtifacts artifacts: "${REPORTS_DIR}/coverage.xml", allowEmptyArchive: true
                }
            }
        }

        // =========================================================================
        // STAGE 4 — SCAN : Trivy + OWASP Dependency Check
        // FIX: Trivy via docker run (pas d'agent docker pour éviter le socket)
        // =========================================================================
        stage('Scan Securite') {
            parallel {

                // ── Trivy via docker run (accès socket Docker direct) ──
                stage('Trivy') {
                    steps {
                        echo 'Scan vulnerabilites avec Trivy...'
                        sh '''
                            # Charger l image buildee precedemment
                            docker load < image.tar.gz

                            LOADED_IMAGE=$(docker images \
                                --format "{{.Repository}}:{{.Tag}}" \
                                | grep "${IMAGE_NAME}" | head -1)
                            echo "Image a scanner : ${LOADED_IMAGE}"

                            mkdir -p ${REPORTS_DIR}

                            # Scan vulnerabilites OS + librairies
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v "$(pwd)/${REPORTS_DIR}":/reports \
                                aquasec/trivy:0.51.4 \
                                image \
                                --severity "${TRIVY_SEVERITY}" \
                                --format json \
                                --output /reports/trivy-vuln-report.json \
                                --exit-code 1 \
                                --no-progress \
                                "${LOADED_IMAGE}"

                            # Scan secrets dans l image
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v "$(pwd)/${REPORTS_DIR}":/reports \
                                aquasec/trivy:0.51.4 \
                                image \
                                --scanners secret \
                                --format json \
                                --output /reports/trivy-secret-report.json \
                                --exit-code 1 \
                                --no-progress \
                                "${LOADED_IMAGE}"
                        '''
                    }
                    post {
                        always { archiveArtifacts artifacts: "${REPORTS_DIR}/trivy-*.json", allowEmptyArchive: true }
                        success { echo 'Trivy : aucune vulnerabilite CRITICAL/HIGH detectee' }
                        failure { echo 'Trivy : vulnerabilites critiques detectees !' }
                    }
                }

                // ── OWASP Dependency Check ──
                stage('OWASP DC') {
                    options { retry(3) }
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
                                --out ${REPORTS_DIR}/ \
                                --failOnCVSS 7 \
                                --enableRetired || true
                        '''
                    }
                    post {
                        always { archiveArtifacts artifacts: "${REPORTS_DIR}/dependency-check-report.*", allowEmptyArchive: true }
                    }
                }
            }
        }

        stage('Signature Cosign') {
            steps {
                withCredentials([
                    usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'DOCKER_HUB_USER', passwordVariable: 'DOCKER_HUB_PASS'),
                    file(credentialsId: 'cosign-private-key', variable: 'COSIGN_KEY_FILE'),
                    file(credentialsId: 'cosign-public-key',  variable: 'COSIGN_PUB_FILE'),
                    string(credentialsId: 'cosign-password',  variable: 'COSIGN_PASSWORD')
                ]) {
                    sh '''
                        # CORRECTION : Installation de Cosign avec retry via curl
                        COSIGN_VERSION="v2.2.4"
                        curl --retry 5 --retry-delay 5 -sLO "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
                        chmod +x cosign-linux-amd64 && mv cosign-linux-amd64 /usr/local/bin/cosign
                        
                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
                        echo "$DOCKER_HUB_PASS" | docker login ${DOCKER_REGISTRY} -u "$DOCKER_HUB_USER" --password-stdin
                        docker push "$IMAGE_FULL"
                        
                        COSIGN_PASSWORD="$COSIGN_PASSWORD" cosign sign --key "$COSIGN_KEY_FILE" --yes "$IMAGE_FULL"
                        cosign verify --key "$COSIGN_PUB_FILE" "$IMAGE_FULL"
                    '''
                }
            }
        }

        stage('Deploiement' ) {
            when { branch 'main' }
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'DOCKER_HUB_USER', passwordVariable: 'DOCKER_HUB_PASS')]) {
                    sh '''
                        IMAGE_FULL="${DOCKER_REGISTRY}/${DOCKER_HUB_USER}/${IMAGE_NAME}:${IMAGE_TAG}"
                        export DOCKER_IMAGE="$IMAGE_FULL"
                        docker compose pull api
                        docker compose up -d --no-deps api
                        # CORRECTION : Health check avec retry
                        curl --retry 10 --retry-delay 5 -sf http://localhost:8000/health || exit 1
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
            sh 'docker rmi $(docker images -q ) --force 2>/dev/null || true'
            cleanWs()
        }
    }
}

