pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
        skipDefaultCheckout(true)
        durabilityHint('MAX_SURVIVABILITY')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    if (!fileExists('Jenkinsfile')) {
                        error('Jenkinsfile missing at repo root.')
                    }
                    def allowed = ['main', 'develop']
                    if (env.BRANCH_NAME && !(env.BRANCH_NAME in allowed)) {
                        error("Branch policy violation: ${env.BRANCH_NAME} not in ${allowed}")
                    }
                }
            }
        }

        stage('Initialize') {
            steps {
                script {
                    // Load values from Jenkins global env/job env, with safe defaults.
                    env.APP_NAME = env.APP_NAME?.trim() ?: 'secure-flask-app'
                    env.APP_PORT = env.APP_PORT?.trim() ?: '3000'
                    env.COVERAGE_MIN = env.COVERAGE_MIN?.trim() ?: '80'
                    env.PYTHON_IMAGE = env.PYTHON_IMAGE?.trim() ?: 'python:3.12-slim'
                    env.TRIVY_CACHE_DIR = env.TRIVY_CACHE_DIR?.trim() ?: '/var/lib/jenkins/.cache/trivy'
                    env.TRIVY_TIMEOUT = env.TRIVY_TIMEOUT?.trim() ?: '5m'
                    env.USE_ECR = env.USE_ECR?.trim() ?: 'true'
                    env.ECR_PUSH_LATEST = env.ECR_PUSH_LATEST?.trim() ?: 'false'
                    env.AWS_REGION = env.AWS_REGION?.trim() ?: 'eu-west-1'
                    env.DEPLOY_CONTAINER = env.DEPLOY_CONTAINER?.trim() ?: 'secure-flask-app'
                    env.EC2_USER = env.EC2_USER?.trim() ?: 'ec2-user'
                    // Credential ID for Jenkins ssh-agent plugin (not SSH username).
                    env.EC2_SSH_CREDENTIALS_ID = env.EC2_SSH_CREDENTIALS_ID?.trim() ?: env.EC2_SSH_CREDENTIAL_ID?.trim() ?: 'ec2-ssh'

                    def missing = []
                    if (!env.REGISTRY?.trim()) {
                        missing << 'REGISTRY'
                    }
                    if (!env.EC2_HOST?.trim()) {
                        missing << 'EC2_HOST'
                    }
                    if (!missing.isEmpty()) {
                        error("Missing required Jenkins environment variables: ${missing.join(', ')}")
                    }

                    env.IMAGE_NAME = "${env.REGISTRY}/${env.APP_NAME}"

                    if (env.USE_ECR.toBoolean()) {
                        def awsCliPresent = sh(returnStatus: true, script: 'command -v aws >/dev/null 2>&1') == 0
                        if (!awsCliPresent) {
                            error('aws CLI is required for ECR')
                        }
                    }
                }
            }
        }

        stage('Install / Build') {
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

        stage('Test') {
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
                        pytest -q --cov=app --cov-report=xml --cov-fail-under="${COVERAGE_MIN}"
                      '
                '''
            }
        }

        stage('Security Gates') {
            steps {
                sh '''
                    set -euo pipefail
                    docker run --rm \
                      -u "$(id -u):$(id -g)" \
                      -v "$PWD:/workspace" \
                      -w /workspace \
                      "${PYTHON_IMAGE}" \
                      bash -lc '
                        . .venv/bin/activate
                        bandit -q -r app --severity-level high
                        pip-audit -r app/requirements.txt
                      '
                    # Trivy checks intentionally disabled for now.
                '''
            }
        }

        stage('Docker Build') {
            steps {
                script {
                    def gitCommit = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    def buildTs = sh(returnStdout: true, script: "date -u +%Y-%m-%dT%H:%M:%SZ").trim()
                    env.IMAGE_TAG = "${env.BUILD_NUMBER}-${gitCommit}"
                    sh """
                        set -euo pipefail
                        docker build -t ${APP_NAME}:${BUILD_NUMBER} \
                          --build-arg BUILD_NUMBER=${BUILD_NUMBER} \
                          --build-arg GIT_COMMIT=${gitCommit} \
                          --build-arg BUILD_TIMESTAMP=${buildTs} \
                          -f app/Dockerfile app
                        docker tag ${APP_NAME}:${BUILD_NUMBER} ${IMAGE_NAME}:${IMAGE_TAG}
                        docker tag ${APP_NAME}:${BUILD_NUMBER} ${IMAGE_NAME}:latest
                    """
                }
            }
        }

        stage('Image Scan') {
            steps {
                sh '''
                    set -euo pipefail
                    # Trivy image scan temporarily disabled.
                    echo "Skipping Trivy image scan."
                '''
            }
        }

        stage('Push Image') {
            steps {
                script {
                    if (!env.IMAGE_TAG?.trim()) {
                        env.IMAGE_TAG = "${env.BUILD_NUMBER}-${sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()}"
                    }
                    if (env.USE_ECR.toBoolean()) {
                        sh '''
                            set -euo pipefail
                            aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
                            docker push ${IMAGE_NAME}:${IMAGE_TAG}
                        '''
                        if (env.ECR_PUSH_LATEST.toBoolean()) {
                            sh 'docker push ${IMAGE_NAME}:latest'
                        } else {
                            echo 'Skipping latest tag push for immutable ECR repository.'
                        }
                        sh 'docker logout "${REGISTRY}"'
                    } else {
                        withCredentials([usernamePassword(credentialsId: 'registry_creds', usernameVariable: 'REGISTRY_USER', passwordVariable: 'REGISTRY_PASS')]) {
                            sh '''
                                set -euo pipefail
                                echo "${REGISTRY_PASS}" | docker login -u "${REGISTRY_USER}" --password-stdin "${REGISTRY}"
                                docker push ${IMAGE_NAME}:${IMAGE_TAG}
                            '''
                            if (env.ECR_PUSH_LATEST.toBoolean()) {
                                sh 'docker push ${IMAGE_NAME}:latest'
                            }
                            sh 'docker logout "${REGISTRY}"'
                        }
                    }
                }
            }
        }

        stage('Deploy to EC2') {
            steps {
                sshagent(credentials: [env.EC2_SSH_CREDENTIALS_ID]) {
                    script {
                        echo "Using SSH credential ID: ${env.EC2_SSH_CREDENTIALS_ID}"
                        if (!env.IMAGE_TAG?.trim()) {
                            env.IMAGE_TAG = "${env.BUILD_NUMBER}-${sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()}"
                        }
                        sh '''
                            set -euo pipefail
                            ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} \
                              "IMAGE_NAME='${IMAGE_NAME}:${IMAGE_TAG}' REGISTRY='${REGISTRY}' APP_NAME='${APP_NAME}' DEPLOY_CONTAINER='${DEPLOY_CONTAINER}' USE_ECR='${USE_ECR}' AWS_REGION='${AWS_REGION}' bash -s" \
                              < scripts/deploy_remote.sh
                        '''
                    }
                }
            }
        }

        stage('Post-Deployment Verification') {
            steps {
                sh '''
                    set -euo pipefail
                    curl -fsS "http://${EC2_HOST}/health"
                '''
            }
        }

        stage('Cleanup') {
            steps {
                sh '''
                    set -euo pipefail
                    docker container prune -f
                    docker image prune -f
                '''
            }
        }
    }

    post {
        failure {
            echo 'Pipeline failed. Review logs for details.'
        }
        always {
            cleanWs()
        }
    }
}
