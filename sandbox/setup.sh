#!/usr/bin/env bash
# =============================================================================
# Detection-as-Code — Sandbox K8s Cluster Setup
#
# Spins up a local kind cluster with MinIO + Loki + Alertmanager,
# builds the detection engine image, and deploys it.
#
# Prerequisites: Docker Desktop running, Homebrew installed
#
# Usage:
#   chmod +x sandbox/setup.sh
#   ./sandbox/setup.sh
#
# Teardown:
#   kind delete cluster --name dac-sandbox
# =============================================================================

set -euo pipefail

CLUSTER_NAME="dac-sandbox"
NAMESPACE="detections"
MONITORING_NS="monitoring"
IMAGE="detection-engine:sandbox"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# ---------------------------------------------------------------------------
# 0. Preflight checks
# ---------------------------------------------------------------------------

preflight() {
  if ! docker info &>/dev/null; then
    err "Docker is not running. Start Docker Desktop first."
  fi
  log "Docker is running"
}

# ---------------------------------------------------------------------------
# 1. Install tools if missing (Homebrew on macOS, curl on Linux)
# ---------------------------------------------------------------------------

install_tool() {
  local name=$1
  if command -v "$name" &>/dev/null; then return; fi

  if command -v brew &>/dev/null; then
    log "Installing $name via Homebrew..."
    brew install "$name"
  else
    # Linux fallback
    ARCH=$(uname -m)
    case $ARCH in
      x86_64) ARCH="amd64" ;;
      aarch64|arm64) ARCH="arm64" ;;
    esac
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')

    case $name in
      kind)
        log "Installing kind..."
        curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.22.0/kind-${OS}-${ARCH}"
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
        ;;
      kubectl)
        log "Installing kubectl..."
        STABLE=$(curl -Ls https://dl.k8s.io/release/stable.txt)
        curl -Lo ./kubectl "https://dl.k8s.io/release/${STABLE}/bin/${OS}/${ARCH}/kubectl"
        chmod +x ./kubectl
        sudo mv ./kubectl /usr/local/bin/kubectl
        ;;
      helm)
        log "Installing helm..."
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
        ;;
    esac
  fi
}

# ---------------------------------------------------------------------------
# 2. Create kind cluster (single node for sandbox)
# ---------------------------------------------------------------------------

create_cluster() {
  if kind get clusters 2>/dev/null | grep -q "$CLUSTER_NAME"; then
    warn "Cluster '$CLUSTER_NAME' exists — reusing"
    kubectl cluster-info --context "kind-$CLUSTER_NAME" &>/dev/null || \
      err "Cluster exists but kubectl can't reach it. Try: kind delete cluster --name $CLUSTER_NAME"
    return
  fi

  log "Creating kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" --wait 60s
  log "Cluster ready"
}

# ---------------------------------------------------------------------------
# 3. Install MinIO (S3-compatible storage for Loki)
# ---------------------------------------------------------------------------

install_minio() {
  log "Installing MinIO in $MONITORING_NS..."
  kubectl create namespace "$MONITORING_NS" --dry-run=client -o yaml | kubectl apply -f -

  kubectl apply -n "$MONITORING_NS" -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: minio-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 5Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minio
  template:
    metadata:
      labels:
        app: minio
    spec:
      containers:
      - name: minio
        image: minio/minio:latest
        args: ["server", "/data", "--console-address", ":9001"]
        env:
        - name: MINIO_ROOT_USER
          value: "loki"
        - name: MINIO_ROOT_PASSWORD
          value: "lokisecret"
        ports:
        - containerPort: 9000
          name: api
        - containerPort: 9001
          name: console
        volumeMounts:
        - name: data
          mountPath: /data
        readinessProbe:
          httpGet:
            path: /minio/health/ready
            port: 9000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: minio-data
---
apiVersion: v1
kind: Service
metadata:
  name: minio
spec:
  selector:
    app: minio
  ports:
  - port: 9000
    targetPort: 9000
    name: api
  - port: 9001
    targetPort: 9001
    name: console
EOF

  log "Waiting for MinIO to be ready..."
  kubectl rollout status deployment/minio -n "$MONITORING_NS" --timeout=120s

  # Create the loki-chunks bucket
  log "Creating loki-chunks bucket..."
  kubectl run minio-setup --rm -i --restart=Never \
    --image=minio/mc:latest \
    -n "$MONITORING_NS" \
    --command -- sh -c '
      mc alias set local http://minio:9000 loki lokisecret &&
      mc mb local/loki-chunks --ignore-existing &&
      mc mb local/loki-ruler --ignore-existing &&
      mc mb local/loki-admin --ignore-existing &&
      echo "Buckets created"
    '

  log "MinIO ready with loki-chunks bucket"
}

# ---------------------------------------------------------------------------
# 4. Install Loki (using MinIO as S3 backend)
# ---------------------------------------------------------------------------

install_loki() {
  log "Installing Loki in $MONITORING_NS..."

  helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
  helm repo update grafana

  helm upgrade --install loki grafana/loki \
    --namespace "$MONITORING_NS" \
    --set loki.auth_enabled=false \
    --set loki.commonConfig.replication_factor=1 \
    --set loki.storage.type=s3 \
    --set loki.storage.s3.endpoint=http://minio.monitoring.svc:9000 \
    --set loki.storage.s3.accessKeyId=loki \
    --set loki.storage.s3.secretAccessKey=lokisecret \
    --set loki.storage.s3.s3ForcePathStyle=true \
    --set loki.storage.s3.insecure=true \
    --set loki.storage.bucketNames.chunks=loki-chunks \
    --set loki.storage.bucketNames.ruler=loki-ruler \
    --set loki.storage.bucketNames.admin=loki-admin \
    --set singleBinary.replicas=1 \
    --set backend.replicas=0 \
    --set read.replicas=0 \
    --set write.replicas=0 \
    --set monitoring.selfMonitoring.enabled=false \
    --set monitoring.selfMonitoring.grafanaAgent.installOperator=false \
    --set test.enabled=false \
    --wait --timeout 300s

  log "Loki ready (backed by MinIO)"
}

# ---------------------------------------------------------------------------
# 5. Install Alertmanager
# ---------------------------------------------------------------------------

install_alertmanager() {
  log "Installing Alertmanager..."
  kubectl apply -n "$MONITORING_NS" -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: alertmanager-config
data:
  alertmanager.yml: |
    global:
      resolve_timeout: 5m
    route:
      receiver: 'default'
      group_by: ['alertname', 'detection_id']
      group_wait: 10s
      group_interval: 5m
      repeat_interval: 1h
    receivers:
    - name: 'default'
      webhook_configs:
      - url: 'http://localhost:9095/webhook'
        send_resolved: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alertmanager
spec:
  replicas: 1
  selector:
    matchLabels:
      app: alertmanager
  template:
    metadata:
      labels:
        app: alertmanager
    spec:
      containers:
      - name: alertmanager
        image: prom/alertmanager:v0.27.0
        ports:
        - containerPort: 9093
        args: ["--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager"]
        volumeMounts:
        - name: config
          mountPath: /etc/alertmanager
      volumes:
      - name: config
        configMap:
          name: alertmanager-config
---
apiVersion: v1
kind: Service
metadata:
  name: alertmanager
spec:
  selector:
    app: alertmanager
  ports:
  - port: 9093
    targetPort: 9093
EOF
  kubectl rollout status deployment/alertmanager -n "$MONITORING_NS" --timeout=60s
  log "Alertmanager ready"
}

# ---------------------------------------------------------------------------
# 6. Build and load the detection engine image
# ---------------------------------------------------------------------------

build_engine() {
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  log "Building detection engine image..."
  docker build -t "$IMAGE" "$REPO_ROOT"
  kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"
  log "Image loaded into cluster"
}

# ---------------------------------------------------------------------------
# 7. Deploy detection engine
# ---------------------------------------------------------------------------

deploy_engine() {
  log "Deploying detection engine..."
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

  kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: detection-engine-config
data:
  LOKI_URL: "http://loki.$MONITORING_NS.svc:3100"
  ALERTMANAGER_URL: "http://alertmanager.$MONITORING_NS.svc:9093/api/v1/alerts"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: detection-engine
  labels:
    app: detection-engine
spec:
  replicas: 1
  selector:
    matchLabels:
      app: detection-engine
  template:
    metadata:
      labels:
        app: detection-engine
    spec:
      containers:
      - name: detection-engine
        image: $IMAGE
        imagePullPolicy: Never
        env:
        - name: LOKI_URL
          valueFrom:
            configMapKeyRef:
              name: detection-engine-config
              key: LOKI_URL
        - name: ALERTMANAGER_URL
          valueFrom:
            configMapKeyRef:
              name: detection-engine-config
              key: ALERTMANAGER_URL
        - name: POLL_INTERVAL
          value: "30"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 200m
            memory: 128Mi
EOF
  kubectl rollout status deployment/detection-engine -n "$NAMESPACE" --timeout=120s
  log "Detection engine deployed"
}

# ---------------------------------------------------------------------------
# 8. Verify
# ---------------------------------------------------------------------------

verify() {
  echo ""
  log "Cluster status:"
  echo ""
  echo "  --- $MONITORING_NS ---"
  kubectl get pods -n "$MONITORING_NS" --no-headers 2>/dev/null | while read -r line; do echo "  $line"; done
  echo ""
  echo "  --- $NAMESPACE ---"
  kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | while read -r line; do echo "  $line"; done
  echo ""
  log "Sandbox ready!"
  echo ""
  echo "  Next steps:"
  echo "    1. Inject test data:"
  echo "       kubectl port-forward -n $MONITORING_NS svc/loki 3100:3100 &"
  echo "       python3 sandbox/inject_cloudtrail.py --loki-url http://localhost:3100 --count 50"
  echo ""
  echo "    2. Watch detection logs:"
  echo "       kubectl logs -n $NAMESPACE -l app=detection-engine -f"
  echo ""
  echo "    3. Check Alertmanager:"
  echo "       kubectl port-forward -n $MONITORING_NS svc/alertmanager 9093:9093 &"
  echo "       curl http://localhost:9093/api/v2/alerts"
  echo ""
  echo "    4. MinIO console (optional):"
  echo "       kubectl port-forward -n $MONITORING_NS svc/minio 9001:9001 &"
  echo "       open http://localhost:9001  (user: loki / pass: lokisecret)"
  echo ""
  echo "    5. Tear down:"
  echo "       kind delete cluster --name $CLUSTER_NAME"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "Detection-as-Code — Sandbox Setup"
  echo ""

  preflight
  for tool in kind kubectl helm; do install_tool "$tool"; done
  create_cluster
  install_minio
  install_loki
  install_alertmanager
  build_engine
  deploy_engine
  verify
}

main "$@"
