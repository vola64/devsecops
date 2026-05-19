// =============================================================================
// Jenkinsfile Corrigé — Résolution des Timeouts Réseau
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
        timeout(time: 30, unit: 'MINUTES')
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

        stage('SAST et Secrets') {
            parallel {

                // CORRECTION : Utilisation d'une image avec Bandit pré-installé
                stage('Bandit') {
                    agent {
                        docker {
                            image 'pipelinecomponents/bandit:latest'
                            reuseNode true
                        }
                    }
                    steps {
                        echo 'Analyse SAST Python avec Bandit (Image Pré-installée)...'
                        sh '''
                            bandit -r src/ \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                -ll \
                                --severity-level medium \
                                || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/bandit-report.json", allowEmptyArchive: true
                        }
                    }
                }

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
                            gitleaks detect --source . --report-format json --report-path ${REPORTS_DIR}/gitleaks-report.json --no-git --verbose
                        '''
                    }
                    post {
                        failure { error 'GITLEAKS : Secrets detectes !' }
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/gitleaks-report.json", allowEmptyArchive: true
                        }
                    }
                }

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
                            semgrep scan --config=p/python --config=p/security-audit --config=p/owasp-top-ten --json --output ${REPORTS_DIR}/semgrep-report.json src/ || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORTS_DIR}/semgrep-report.json", allowEmptyArchive: true
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
            agent {
                docker {
                    image 'python:3.11-slim'
                    reuseNode true
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

        stage('Scan Securite') {
            parallel {
                stage('Trivy') {
                    agent {
                        docker {
                            image 'aquasec/trivy:0.51.4'
                            reuseNode true
                            args '--entrypoint= -v /var/run/docker.sock:/var/run/docker.sock'
                        }
                    }
                    steps {
                        sh '''
                            docker load < image.tar.gz
                            TARGET_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
                            trivy image --severity ${TRIVY_SEVERITY} --format json --output ${REPORTS_DIR}/trivy-vuln-report.json --exit-code 1 "$TARGET_IMAGE"
                        '''
                    }
                    post {
                        always { archiveArtifacts artifacts: "${REPORTS_DIR}/trivy-*.json", allowEmptyArchive: true }
                    }
                }

                stage('OWASP DC') {
                    agent {
                        docker {
                            image 'owasp/dependency-check:latest'
                            reuseNode true
                        }
                    }
                    steps {
                        sh '/usr/share/dependency-check/bin/dependency-check.sh --project "DevSecOps API" --scan . --format JSON --out ${REPORTS_DIR}/ --failOnCVSS 7 --enableRetired || true'
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
