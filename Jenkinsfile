pipeline {
    agent any

    environment {
        // SonarQube
        SONAR_HOST_URL = "http://192.168.50.4:9000"
        SONAR_AUTH_TOKEN = credentials('Sonarr')

        // App & Docker
        APP_PORT = "4000"
        DOCKER_NETWORK = "monitor-net"
        APP_IMAGE = "myapp:latest"
        APP_CONTAINER = "myapp"

        // Reports
        NIKTO_REPORTS = "${WORKSPACE}/nikto-reports"
        TRIVY_REPORTS = "${WORKSPACE}/trivy-reports"

        // Monitoring
        PROMETHEUS_PORT = "9090"
        GRAFANA_PORT = "3000"
    }

    stages {

        // =====================
        // Code Preparation
        // =====================
        stage('Checkout Code') {
            steps {
                git branch: 'main', credentialsId: 'jenkins-git', url: 'https://github.com/Dhia-Ben-Bouali/Devsecops_lab'
            }
        }
        stage('Validate Commit Message') {
            steps {
                script {
                    // Get last commit message
                    def commitMessage = sh(script: "git log -1 --pretty=%B", returnStdout: true).trim()
                    echo "Last commit message: ${commitMessage}"

                    // Define your Slack webhook URL (store securely in Jenkins credentials)
                    def webhookUrl = credentials('slack-webhook') // Jenkins secret text ID

                    // Define helper function to send Slack messages
                    def sendSlackMessage = { color, text ->
                        def safeText = text.replace('"', '\\"').replace('\n', '\\n')
                        writeFile file: 'payload.json', text: """
                    {
                    "attachments": [
                        {
                        "color": "${color}",
                        "text": "${safeText}"
                        }
                    ]
                    }
                    """
                        sh """
                        curl -s -X POST -H 'Content-type: application/json' \
                        --data @payload.json \
                        ${webhookUrl}
                        """
                    }

                    if (!commitMessage.contains("devsecops_lab")) {
                        echo "❌ Commit message does not match 'devsecops_lab'. Aborting pipeline."

                        sendSlackMessage(
                            "#FF0000",
                            "🚫 *Pipeline skipped!* Commit message did not contain 'devsecops_lab'.\\n*Commit:* `${commitMessage}`"
                        )

                        currentBuild.result = 'SUCCESS'
                        error("Pipeline skipped due to commit message filter")
                    } else {
                        echo "✅ Commit message matched. Continuing pipeline..."

                        sendSlackMessage(
                            "#36a64f",
                            "✅ *Commit message validation passed!* Proceeding with the pipeline.\\n*Commit:* `${commitMessage}`"
                        )
                    }
                }
            }
        }

        // =====================
        // Install & Build
        // =====================
        stage('Install Dependencies') {
            steps { sh 'npm install' }
        }

        stage('Build') {
            steps { sh 'npm run build' }
        }

        stage('Test') {
            steps { sh 'npm test || true' } // Continue even if tests fail
        }

        // =====================
        // Static Analysis
        // =====================
        stage('SonarQube Analysis') {
            steps {
                sh """
                    npx sonar-scanner \
                        -Dsonar.projectKey=devops_lab \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=${SONAR_HOST_URL} \
                        -Dsonar.login=${SONAR_AUTH_TOKEN}
                """
            }
        }

        // =====================
        // Docker Setup
        // =====================
        stage('Prepare Docker Network') {
            steps {
                sh "docker rm -f ${APP_CONTAINER} || true"
                sh "docker network inspect ${DOCKER_NETWORK} || docker network create ${DOCKER_NETWORK}"
            }
        }

        stage('Build Docker Image') {
            steps { sh "docker build -t ${APP_IMAGE} ." }
        }

        // =====================
        // Monitoring Stack
        // =====================
        stage('Run Monitoring Stack') {
            steps {
                script {
                    echo '📈 Setting up Prometheus + Grafana + cAdvisor...'

                    def containers = ['prometheus': '9090', 'cadvisor': '5050', 'grafana': '3000']

                    containers.each { name, port ->
                        def exists = sh(script: "docker ps -a --filter name=${name} -q", returnStdout: true).trim()
                        if (!exists) {
                            def runCmd = ""
                            if (name == 'prometheus') {
                                runCmd = """
                                    docker run -d --name prometheus \
                                        --network ${DOCKER_NETWORK} \
                                        -p ${PROMETHEUS_PORT}:9090 \
                                        -v ${WORKSPACE}/prometheus.yml:/etc/prometheus/prometheus.yml \
                                        prom/prometheus
                                """
                            } else if (name == 'cadvisor') {
                                runCmd = """
                                    docker run -d --name cadvisor \
                                        --volume=/:/rootfs:ro \
                                        --volume=/var/run/docker.sock:/var/run/docker.sock:ro \
                                        --volume=/var/lib/docker/:/var/lib/docker:ro \
                                        --volume=/sys:/sys:ro \
                                        --network ${DOCKER_NETWORK} \
                                        -p 5050:8080 \
                                        gcr.io/cadvisor/cadvisor:latest
                                """
                            } else if (name == 'grafana') {
                                runCmd = """
                                    docker run -d --name grafana \
                                        --network ${DOCKER_NETWORK} \
                                        -p ${GRAFANA_PORT}:3000 \
                                        grafana/grafana
                                """
                            }
                            sh runCmd
                            echo "✅ ${name} started."
                        } else {
                            echo "✅ ${name} already running."
                        }
                    }
                }
            }
        }

        // =====================
        // Run Application
        // =====================
        stage('Run App Container') {
            steps {
                script {
                    sh "docker rm -f ${APP_CONTAINER} || true"
                    sh """
                        docker run -d --name ${APP_CONTAINER} \
                            --network ${DOCKER_NETWORK} \
                            -p ${APP_PORT}:${APP_PORT} \
                            ${APP_IMAGE}
                    """

                    echo '⏳ Waiting for application to respond...'

                    def maxRetries = 30
                    def sleepTime = 2
                    def appUp = false

                    for (int i = 1; i <= maxRetries; i++) {
                        def response = sh(
                            script: "curl -s -o /dev/null -w '%{http_code}' http://localhost:${APP_PORT}/ || true",
                            returnStdout: true
                        ).trim()

                        if (response == '200' || response == '404') {
                            echo "✅ Application is up!"
                            appUp = true
                            break
                        }

                        echo "Waiting for app... (${i}/${maxRetries})"
                        sleep sleepTime
                    }

                    if (!appUp) {
                        echo "❌ Application did not respond in time."
                        sh "docker logs ${APP_CONTAINER} --tail 50 || true"
                        error("App failed to start")
                    }
                }
            }
        }

        // =====================
        // Security Scans
        // =====================
        stage('Nikto Web Server Scan') {
            steps {
                script {
                    echo '🔍 Running Nikto scan on web server...'
                    sh "mkdir -p ${NIKTO_REPORTS}"
                    sh """
                        docker run --rm -u 0:0 \
                            --network ${DOCKER_NETWORK} \
                            -v ${NIKTO_REPORTS}:/nikto-reports \
                            ghcr.io/sullo/nikto:latest \
                            -h http://${APP_CONTAINER}:${APP_PORT} \
                            -o /nikto-reports/nikto-report.txt
                    """
                    archiveArtifacts artifacts: 'nikto-reports/**', allowEmptyArchive: true
                    echo '✅ Nikto scan finished, report archived.'
                }
            }
        }

        stage('Trivy Security Scan') {
            steps {
                script {
                    echo '🔍 Running Trivy scan on Docker image (pipeline continues)...'
                    sh "mkdir -p ${TRIVY_REPORTS}"
                    sh """
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                            -v ${TRIVY_REPORTS}:/trivy-reports \
                            aquasec/trivy:latest \
                            image --exit-code 0 --severity HIGH,CRITICAL \
                            -f json -o /trivy-reports/trivy-report.json ${APP_IMAGE}
                    """
                    archiveArtifacts artifacts: 'trivy-reports/**', allowEmptyArchive: true
                    echo '✅ Trivy scan finished, report archived.'
                }
            }
        }

        // =====================
        // Deployment
        // =====================
        stage('Deploy') {
            steps { echo 'Deployment step (to be customized later)' }
        }

    } // end stages

    post {
        always {
            echo 'Pipeline finished — containers are still running for monitoring.'
            sh 'docker ps -a'
        }
    }
}
