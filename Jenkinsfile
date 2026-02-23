// ---------------------------------------------------------------------------
// Secure CI/CD Pipeline — ECS + SAST/SCA
//
// Security gates (each fails the pipeline when triggered):
//   • Gitleaks     — any secret/credential committed to git
//   • Bandit       — Python SAST, HIGH+ severity
//   • pip-audit    — SCA, any known CVE in requirements
//   • Trivy        — container image CRITICAL/HIGH CVEs (fixed or unfixed)
//
// Deliverables archived per build:
//   reports/gitleaks-report.json
//   reports/bandit-report.json
//   reports/pip-audit-report.json
//   reports/trivy-report.json
//   reports/sbom.json  (CycloneDX / Syft)
//
// Target runtime: Amazon ECS Fargate (rolling update via AWS CLI)
// ---------------------------------------------------------------------------
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
        skipDefaultCheckout(true)
        durabilityHint('MAX_SURVIVABILITY')
    }

    // -----------------------------------------------------------------------
    // Pinned tool image versions — update here to upgrade across all stages
    // -----------------------------------------------------------------------
    environment {
        GITLEAKS_IMAGE = 'zricethezav/gitleaks:v8.24.0'
        TRIVY_IMAGE    = 'aquasec/trivy:0.60.0'
        SYFT_IMAGE     = 'anchore/syft:v1.19.0'
        REPORTS_DIR    = 'reports'
    }

    stages {

        // -------------------------------------------------------------------
        stage('Checkout') {
        // -------------------------------------------------------------------
            steps {
                checkout scm
                script {
                    if (!fileExists('Jenkinsfile')) {
                        error('Jenkinsfile missing at repo root.')
                    }
                    def allowed = ['main', 'develop', 'feat/security-gitops']
                    if (env.BRANCH_NAME && !(env.BRANCH_NAME in allowed)) {
                        error("Branch policy violation: ${env.BRANCH_NAME} not in ${allowed}")
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        stage('Initialize') {
        // -------------------------------------------------------------------
            steps {
                script {
                    env.APP_NAME          = env.APP_NAME?.trim()          ?: 'secure-flask-app'
                    env.APP_PORT          = env.APP_PORT?.trim()          ?: '3000'
                    env.COVERAGE_MIN      = env.COVERAGE_MIN?.trim()      ?: '80'
                    env.PYTHON_IMAGE      = env.PYTHON_IMAGE?.trim()      ?: 'python:3.12-slim'
                    env.TRIVY_CACHE_DIR   = env.TRIVY_CACHE_DIR?.trim()   ?: '/var/lib/jenkins/.cache/trivy'
                    env.AWS_REGION        = env.AWS_REGION?.trim()        ?: 'eu-west-1'
                    env.MONITORING_HOST_DNS = env.MONITORING_HOST_DNS?.trim() ?: ''

                    // ECS-specific (all sourced from Terraform outputs → Jenkins env vars)
                    env.ECS_CLUSTER_NAME      = env.ECS_CLUSTER_NAME?.trim()      ?: ''
                    env.ECS_SERVICE_NAME      = env.ECS_SERVICE_NAME?.trim()      ?: ''
                    env.ECS_EXECUTION_ROLE_ARN = env.ECS_EXECUTION_ROLE_ARN?.trim() ?: ''
                    env.ECS_TASK_ROLE_ARN     = env.ECS_TASK_ROLE_ARN?.trim()     ?: ''
                    env.ECS_LOG_GROUP         = env.ECS_LOG_GROUP?.trim()         ?: "/ecs/${env.APP_NAME}"
                    env.ALB_DNS_NAME          = env.ALB_DNS_NAME?.trim()          ?: ''

                    def missing = []
                    ['REGISTRY', 'AWS_REGION',
                     'ECS_CLUSTER_NAME', 'ECS_SERVICE_NAME',
                     'ECS_EXECUTION_ROLE_ARN', 'ECS_TASK_ROLE_ARN',
                     'ALB_DNS_NAME'].each { v ->
                        if (!env[v]?.trim()) missing << v
                    }
                    if (!missing.isEmpty()) {
                        error("Missing required Jenkins global env vars: ${missing.join(', ')}")
                    }

                    env.IMAGE_NAME = "${env.REGISTRY}/${env.APP_NAME}"

                    def awsOk = sh(returnStatus: true, script: 'command -v aws >/dev/null 2>&1') == 0
                    if (!awsOk) error('aws CLI is required')

                    sh 'mkdir -p "${REPORTS_DIR}"'
                    echo "Pipeline initialised — image base: ${env.IMAGE_NAME}"
                }
            }
        }

        // -------------------------------------------------------------------
        stage('Secret Scan') {
        // -------------------------------------------------------------------
        // Gate: any secret (API keys, tokens, passwords) committed → FAIL
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== Gitleaks secret scan ==="
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "${PWD}:/workspace:ro" \
                      "${GITLEAKS_IMAGE}" detect \
                        --source /workspace \
                        --config /workspace/.gitleaks.toml \
                        --report-path /workspace/${REPORTS_DIR}/gitleaks-report.json \
                        --report-format json \
                        --exit-code 1 \
                        --no-git
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Install / Build') {
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "$PWD:/workspace" \
                      -w /workspace \
                      "${PYTHON_IMAGE}" \
                      bash -lc '
                        python -m venv .venv
                        . .venv/bin/activate
                        pip install --upgrade pip
                        pip install -r app/requirements.txt -r app/requirements-dev.txt
                        pip check
                      '
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Unit Tests') {
        // -------------------------------------------------------------------
        // Gate: coverage below ${COVERAGE_MIN}% → FAIL
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "$PWD:/workspace" \
                      -w /workspace \
                      -e COVERAGE_MIN="${COVERAGE_MIN}" \
                      "${PYTHON_IMAGE}" \
                      bash -lc '
                        . .venv/bin/activate
                        export PYTHONPATH=/workspace
                        pytest -q \
                          --cov=app \
                          --cov-report=xml:${REPORTS_DIR}/coverage.xml \
                          --cov-fail-under="${COVERAGE_MIN}"
                      '
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('SAST — Bandit') {
        // -------------------------------------------------------------------
        // Gate: any finding with severity HIGH or CRITICAL → FAIL
        // Reports saved to reports/bandit-report.json
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== Bandit SAST scan ==="
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "$PWD:/workspace" \
                      -w /workspace \
                      "${PYTHON_IMAGE}" \
                      bash -lc '
                        . .venv/bin/activate
                        bandit -r app \
                          --severity-level high \
                          --format json \
                          --output ${REPORTS_DIR}/bandit-report.json \
                          --exit-zero
                        # Re-run without --exit-zero to enforce the gate
                        bandit -r app --severity-level high -q
                      '
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('SCA — pip-audit') {
        // -------------------------------------------------------------------
        // Gate: any CVE found in requirements → FAIL
        // Reports saved to reports/pip-audit-report.json
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== pip-audit SCA scan ==="
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "$PWD:/workspace" \
                      -w /workspace \
                      "${PYTHON_IMAGE}" \
                      bash -lc '
                        . .venv/bin/activate
                        pip-audit \
                          -r app/requirements.txt \
                          --format json \
                          --output ${REPORTS_DIR}/pip-audit-report.json \
                          --progress-spinner off
                      '
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Docker Build') {
        // -------------------------------------------------------------------
            steps {
                script {
                    def gitCommit = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    def buildTs   = sh(returnStdout: true, script: "date -u +%Y-%m-%dT%H:%M:%SZ").trim()
                    env.IMAGE_TAG = "${env.BUILD_NUMBER}-${gitCommit}"
                    sh """
                        set -euo pipefail
                        docker build \
                          -t ${APP_NAME}:${BUILD_NUMBER} \
                          --build-arg BUILD_NUMBER=${BUILD_NUMBER} \
                          --build-arg GIT_COMMIT=${gitCommit} \
                          --build-arg BUILD_TIMESTAMP=${buildTs} \
                          -f app/Dockerfile app
                        docker tag ${APP_NAME}:${BUILD_NUMBER} ${IMAGE_NAME}:${IMAGE_TAG}
                    """
                }
            }
        }

        // -------------------------------------------------------------------
        stage('SBOM — Syft') {
        // -------------------------------------------------------------------
        // Generates a CycloneDX JSON SBOM and archives it. No gate.
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== Syft SBOM generation ==="
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      "${SYFT_IMAGE}" \
                        "${IMAGE_NAME}:${IMAGE_TAG}" \
                        -o cyclonedx-json \
                      > "${REPORTS_DIR}/sbom.json"
                    echo "SBOM generated: $(wc -l < ${REPORTS_DIR}/sbom.json) lines"
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Image Scan — Trivy') {
        // -------------------------------------------------------------------
        // Gate: any CRITICAL or HIGH CVE → FAIL
        // Reports saved to reports/trivy-report.json regardless of outcome
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== Trivy image scan ==="
                    mkdir -p "${TRIVY_CACHE_DIR}" "${REPORTS_DIR}"
                    # Write JSON report directly to workspace via volume mount
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      -v "${TRIVY_CACHE_DIR}:/root/.cache/trivy" \
                      -v "${PWD}/${REPORTS_DIR}:/reports" \
                      "${TRIVY_IMAGE}" image \
                        --exit-code 1 \
                        --severity CRITICAL,HIGH \
                        --format json \
                        --output /reports/trivy-report.json \
                        "${IMAGE_NAME}:${IMAGE_TAG}"
                    echo "Trivy: no CRITICAL/HIGH CVEs — gate passed."
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Push Image') {
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    aws ecr get-login-password --region "${AWS_REGION}" \
                      | docker login --username AWS --password-stdin "${REGISTRY}"
                    docker push "${IMAGE_NAME}:${IMAGE_TAG}"
                    docker logout "${REGISTRY}"
                    echo "Pushed: ${IMAGE_NAME}:${IMAGE_TAG}"
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('ECS Deploy') {
        // -------------------------------------------------------------------
        // 1. Render infra/ecs/task-definition.json with build-specific values
        // 2. Register a new task definition revision
        // 3. Update the ECS service to use it (rolling update)
        // 4. Wait for the service to stabilise
        // -------------------------------------------------------------------
            steps {
                script {
                    def otlpEndpoint = env.MONITORING_HOST_DNS?.trim()
                        ? "http://${env.MONITORING_HOST_DNS}:4317"
                        : ''
                    withEnv([
                        "IMAGE_URI=${env.IMAGE_NAME}:${env.IMAGE_TAG}",
                        "EXECUTION_ROLE_ARN=${env.ECS_EXECUTION_ROLE_ARN}",
                        "TASK_ROLE_ARN=${env.ECS_TASK_ROLE_ARN}",
                        "LOG_GROUP=${env.ECS_LOG_GROUP}",
                        "OTLP_ENDPOINT=${otlpEndpoint}",
                    ]) {
                        sh '''
                            set -euo pipefail

                            # --- Render task definition -----------------------
                            python3 - <<'PYEOF'
import os

with open('infra/ecs/task-definition.json') as f:
    content = f.read()

# Simple token substitution: replace ${VAR} with env value
for key, val in os.environ.items():
    content = content.replace('${' + key + '}', val)

with open('rendered-task-def.json', 'w') as f:
    f.write(content)

print("Task definition rendered -> rendered-task-def.json")
PYEOF

                            # --- Register new revision -----------------------
                            TASK_DEF_ARN=$(aws ecs register-task-definition \
                              --cli-input-json file://rendered-task-def.json \
                              --region "${AWS_REGION}" \
                              --query 'taskDefinition.taskDefinitionArn' \
                              --output text)
                            echo "Registered: ${TASK_DEF_ARN}"
                            echo "${TASK_DEF_ARN}" > task-def-arn.txt

                            # --- Update service (rolling) --------------------
                            aws ecs update-service \
                              --cluster  "${ECS_CLUSTER_NAME}" \
                              --service  "${ECS_SERVICE_NAME}" \
                              --task-definition "${TASK_DEF_ARN}" \
                              --force-new-deployment \
                              --region   "${AWS_REGION}" \
                              --output text > /dev/null
                            echo "Service update requested — waiting for stable state..."

                            # --- Wait (up to 10 minutes) --------------------
                            aws ecs wait services-stable \
                              --cluster  "${ECS_CLUSTER_NAME}" \
                              --services "${ECS_SERVICE_NAME}" \
                              --region   "${AWS_REGION}"
                            echo "ECS service is stable."
                        '''
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        stage('Smoke Test') {
        // -------------------------------------------------------------------
        // Verify the new deployment is healthy via the ALB
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail
                    echo "=== Smoke test: GET http://${ALB_DNS_NAME}/health ==="
                    for i in $(seq 1 12); do
                        STATUS=$(curl -o /dev/null -fsS -w "%{http_code}" \
                                 "http://${ALB_DNS_NAME}/health" 2>/dev/null || true)
                        if [ "${STATUS}" = "200" ]; then
                            echo "Health check passed (HTTP ${STATUS}) after ${i} attempt(s)."
                            exit 0
                        fi
                        echo "Attempt ${i}/12: HTTP ${STATUS:-timeout} — retrying in 10s"
                        sleep 10
                    done
                    echo "ERROR: Health check failed after 12 attempts."
                    exit 1
                '''
            }
        }

        // -------------------------------------------------------------------
        stage('Cleanup') {
        // -------------------------------------------------------------------
        // • Deregister old ECS task definition revisions (keep last 5)
        // • Prune local Docker artefacts
        // ECR image lifecycle is managed by the aws_ecr_lifecycle_policy
        // Terraform resource (keep 10 tagged, expire untagged after 1 day).
        // -------------------------------------------------------------------
            steps {
                sh '''
                    set -euo pipefail

                    # --- Deregister old ECS task definition revisions --------
                    FAMILY="${APP_NAME}"
                    ALL_REVS=$(aws ecs list-task-definitions \
                      --family-prefix "${FAMILY}" \
                      --status ACTIVE \
                      --sort ASC \
                      --region "${AWS_REGION}" \
                      --query 'taskDefinitionArns[]' \
                      --output text)

                    COUNT=$(echo "${ALL_REVS}" | wc -w)
                    KEEP=5
                    if [ "${COUNT}" -gt "${KEEP}" ]; then
                        TO_DEREGISTER=$(echo "${ALL_REVS}" | tr '\\t' '\\n' | head -n $((COUNT - KEEP)))
                        for ARN in ${TO_DEREGISTER}; do
                            aws ecs deregister-task-definition \
                              --task-definition "${ARN}" \
                              --region "${AWS_REGION}" \
                              --output text > /dev/null
                            echo "Deregistered: ${ARN}"
                        done
                    else
                        echo "Only ${COUNT} revision(s) — nothing to deregister."
                    fi

                    # --- Prune local Docker resources -------------------------
                    docker container prune -f
                    docker image prune -f
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts(
                artifacts: "${REPORTS_DIR}/**",
                allowEmptyArchive: true,
                fingerprint: true
            )
            cleanWs()
        }
        success {
            echo """
Pipeline succeeded.
  Image  : ${env.IMAGE_NAME}:${env.IMAGE_TAG ?: 'N/A'}
  App URL: http://${env.ALB_DNS_NAME ?: 'N/A'}/health
  Reports: ${env.REPORTS_DIR}/
"""
        }
        failure {
            echo 'Pipeline FAILED — review archived security reports and stage logs.'
        }
    }
}
