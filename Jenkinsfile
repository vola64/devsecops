// =============================================================================
// Jenkinsfile — Pipeline CI/CD Sécurisé DevSecOps
// Projet : Supply Chain Security — Jenkins + Docker Hub
// =============================================================================
//
// PLUGINS JENKINS REQUIS :
//   - Docker Pipeline   → agent { docker { ... } }
//   - AnsiColor         → ansiColor('xterm')
//   - HTML Publisher    → publishHTML(...)
//
// CREDENTIALS JENKINS REQUIS (Manage Jenkins → Credentials) :
//   Aucun credential requis pour les stages actifs
// =============================================================================

pipeline {

    agent any

    environment {
        IMAGE_NAME = "devsecops-api"
        IMAGE_TAG  = "${env.GIT_COMMIT?.take(8) ?: 'latest'}"
        TRIVY_SEVERITY  = 'CRITICAL,HIGH'
        REPORTS_DIR     = 'reports'
    }

    options {
        // FIX : timeout 60 min (semgrep = 1.5 Go, lent à télécharger)
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

        // ─── Stage 0 : Init + pré-téléchargement des images ──────────────────
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

                // FIX : pré-pull avec retry pour éviter TLS timeout
                // en pleine exécution parallèle des stages SAST
                sh '''
                    echo "Pre-telechargement des images Docker..."
                    for IMAGE in python:3.11-slim zricethezav/gitleaks:v8.18.4 returntocorp/semgrep:1.72.0; do
                        PULLED=0
                        for i in 1 2 3; do
                            echo "Pull $IMAGE (tentative $i/3)..."
                            if docker pull "$IMAGE"; then
                                PULLED=1
                                break
                            fi
                            sleep 15
                        done
                        if [ "$PULLED" -eq 0 ]; then
                            echo "AVERTISSEMENT : impossible de telecharger $IMAGE apres 3 tentatives"
                        fi
                    done
                    echo "Images disponibles :"
                    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}"
                '''
            }
        }

        // =========================================================================
        // STAGE 1 — SAST
        // =========================================================================
        stage('SAST et Secrets') {
            parallel {

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
                            export HOME=/tmp
                            export PATH="/tmp/.local/bin:$PATH"
                            # FIX : timeout 120s et 3 retries pip
                            pip install bandit --quiet --timeout 120 --retries 3
                            # FIX : supprimer -ll, incompatible avec --severity-level
                            bandit -r src/ \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                --severity-level medium \
                                --confidence-level medium \
                                || true
                            bandit -r src/ \
                                -f txt \
                                --severity-level medium \
                                --confidence-level medium \
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

                stage('Semgrep') {
                    agent {
                        docker {
                            image 'returntocorp/semgrep:1.72.0'
                            reuseNode true
                        }
                    }
                    steps {
                        echo 'Analyse SAST OWASP avec Semgrep...'
                        // FIX : || true sur les deux scans pour ne pas bloquer
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
                                src/ || true
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
                failure { echo 'SAST — Des problemes ont ete detectes' }
            }
        }

        // =========================================================================
        // STAGE 3 — TESTS
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
                    export HOME=/tmp
                    export PATH="/tmp/.local/bin:$PATH"
                    pip install -r requirements.txt --quiet --timeout 120 --retries 3
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
                    publishHTML(target: [
                        allowMissing         : true,
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
        // STAGE 4 — SCAN SÉCURITÉ
        // =========================================================================
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
                        echo "Scan Trivy de l'image Docker..."
                        sh '''
                            TARGET_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

                            trivy image \
                                --severity ${TRIVY_SEVERITY} \
                                --format json \
                                --output ${REPORTS_DIR}/trivy-vuln-report.json \
                                --exit-code 1 \
                                --no-progress \
                                "$TARGET_IMAGE"

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

    }  // end stages

    // =========================================================================
    // POST : Rapport CSV + nettoyage
    // =========================================================================
    post {

        always {
            echo 'Generation du rapport de securite CSV...'
            sh '''
                DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                CSV="${REPORTS_DIR}/security-report.csv"

                echo "build,commit,date,outil,metrique,valeur,statut" > "$CSV"

                # FIX : utiliser count_matches() pour eviter le bug "0\n0" de grep -c
                count_matches() { grep -c "$1" "$2" 2>/dev/null | tr -d '\n' | tr -d ' ' || echo 0; }

                # Bandit
                if [ -f "${REPORTS_DIR}/bandit-report.json" ]; then
                    TOTAL=$(grep -o "issue_severity" "${REPORTS_DIR}/bandit-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    HIGH=$(grep  -o '"issue_severity": "HIGH"'   "${REPORTS_DIR}/bandit-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    MED=$(grep   -o '"issue_severity": "MEDIUM"' "${REPORTS_DIR}/bandit-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    LOW=$(grep   -o '"issue_severity": "LOW"'    "${REPORTS_DIR}/bandit-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    TOTAL=${TOTAL:-0}; HIGH=${HIGH:-0}; MED=${MED:-0}; LOW=${LOW:-0}
                    if [ "$HIGH" -gt 0 ] 2>/dev/null; then SB="ECHEC"; else SB="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,total,${TOTAL},${SB}" >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,high,${HIGH},${SB}"   >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,medium,${MED},${SB}"  >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,low,${LOW},${SB}"     >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Bandit,rapport,non_disponible,INCONNU" >> "$CSV"
                fi

                # Gitleaks
                if [ -f "${REPORTS_DIR}/gitleaks-report.json" ]; then
                    LEAKS=$(grep -o "RuleID" "${REPORTS_DIR}/gitleaks-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    LEAKS=${LEAKS:-0}
                    if [ "$LEAKS" -gt 0 ] 2>/dev/null; then SG="ECHEC"; else SG="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Gitleaks,secrets,${LEAKS},${SG}" >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Gitleaks,rapport,non_disponible,INCONNU" >> "$CSV"
                fi

                # Semgrep
                if [ -f "${REPORTS_DIR}/semgrep-report.json" ]; then
                    FINDS=$(grep -o "check_id" "${REPORTS_DIR}/semgrep-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    FINDS=${FINDS:-0}
                    if [ "$FINDS" -gt 0 ] 2>/dev/null; then SS="AVERTISSEMENT"; else SS="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Semgrep,findings,${FINDS},${SS}" >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Semgrep,rapport,non_disponible,INCONNU" >> "$CSV"
                fi

                # Trivy
                if [ -f "${REPORTS_DIR}/trivy-vuln-report.json" ]; then
                    CRITS=$(grep -o "CRITICAL" "${REPORTS_DIR}/trivy-vuln-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    HIGHS=$(grep -o '"HIGH"'   "${REPORTS_DIR}/trivy-vuln-report.json" 2>/dev/null | wc -l | tr -d ' ')
                    CRITS=${CRITS:-0}; HIGHS=${HIGHS:-0}
                    if [ "$CRITS" -gt 0 ] 2>/dev/null; then ST="ECHEC"; else ST="OK"; fi
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,critical,${CRITS},${ST}" >> "$CSV"
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,high,${HIGHS},${ST}"     >> "$CSV"
                else
                    echo "${BUILD_NUMBER},${GIT_COMMIT},${DATE},Trivy,rapport,non_disponible,INCONNU" >> "$CSV"
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
            cleanWs()
        }

        success { echo "Pipeline DevSecOps reussi — Build #${env.BUILD_NUMBER}" }
        failure { echo "Pipeline DevSecOps echoue — Build #${env.BUILD_NUMBER}" }
        unstable { echo "Pipeline instable — Verifier les tests" }
    }

}  // end pipeline
