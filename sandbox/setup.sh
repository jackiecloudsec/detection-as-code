#!/usr/bin/env bash
# =============================================================================
# Detection-as-Code — Sandbox K8s Cluster Setup
#
# Spins up a local kind cluster with Loki + Alertmanager,
# builds the detection engine image, and deploys it.
#
# Prerequisites: Docker Desktop running
#
# Usage:
#   chmod +x sandbox/setup.sh
#   ./sandbox/setup.sh
# =============================================================================

set -euo pipefail

CLUSTER_NAME="dac-sandbox"
NAMESPACE="detections"
MONITORING_NS="monitoring"
IMAGE="detection-engine:sandbox"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# ---------------------------------------------------------------------------
# 1. Install tools if missing
# ---------------------------------------------------------------------------

install_tool() {
  local name=$1
  if command -v "$name" &>/dev/null; then return; fi

  ARCH=$(uname -m)
  case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
  esac
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')

  case $name in
    kind)
      log "Installing kind..."
      curl -Lo /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/v0.22.0/kind-${OS}-${ARCH}"
      chmod +x /usr/local/bin/kind
      ;;
    kubectl)
      log "Installing kubectl..."
      STABLE=$(curl -Ls https://dl.k8s.io/release/stable.txt)
      curl -Lo /usr/local/bin/kubectl "https://dl.k8s.io/release/${STABLE}/bin/${OS}/${ARCH}/kubectl"
      chmod +x /usr/local/bin/kubectl
      ;;
    helm)
      log "Installing helm..."
      curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 2. Create kind cluster
# ---------------------------------------------------------------------------

create_cluster() {
  if kind get clusters 2>/dev/null | grep -q "$CLUSTER_NAME"; then
    warn "Cluster '$CLUSTER_NAME' exists — reusing"
    return
  fi

  log "Creating kind cluster: $CLUSTER_NAME (1 control-plane + 2 workers)"
  kind create cluster --name "$CLUSTER_NAME" --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF
  log "Cluster ready"
}

# ---------------------------------------------------------------------------
# 3. Install Loki + Alertmanager
# ---------------------------------------------------------------------------

install_loki() {
  log "Installing Loki in $MONITORING_NS..."
  kubectl create namespace "$MONITORING_NS" --dry-run=client -o yaml | kubectl apply -f -

  helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
  helm repo update grafana

  helm upgrade --install loki grafana/loki \
    --namespace "$MONITORING_NS" \
    --set loki.auth_enabled=false \
    --set loki.commonConfig.replication_factor=1 \
    --set singleBinary.replicas=1 \
    --set backend.replicas=0 \
    --set read.replicas=0 \
    --set write.replicas=0 \
    --set monitoring.selfMonitoring.enabled=false \
    --set monitoring.selfMonitoring.grafanaAgent.installOperator=false \
    --set test.enabled=false \
    --wait --timeout 180s
  log "Loki ready"
}

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
  log "Alertmanager ready"
}

# ---------------------------------------------------------------------------
# 4. Build and load the detection engine image
# ---------------------------------------------------------------------------

build_engine() {
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  log "Building detection engine image..."
  docker build -t "$IMAGE" "$REPO_ROOT"
  kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"
  log "Image loaded into cluster"
}

# ---------------------------------------------------------------------------
# 5. Deploy detection engine
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
  log "Detection engine deployed"
}

# ---------------------------------------------------------------------------
# 6. Verify
# ---------------------------------------------------------------------------

verify() {
  echo ""
  log "Cluster status:"
  kubectl get pods -n "$MONITORING_NS" --no-headers 2>/dev/null | while read line; do echo "  $line"; done
  kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | while read line; do echo "  $line"; done
  echo ""
  log "Sandbox ready!"
  echo ""
  echo "  Next steps:"
  echo "    1. Inject test data:"
  echo "       kubectl port-forward -n $MONITORING_NS svc/loki 3100:3100 &"
  echo "       python sandbox/inject_cloudtrail.py --loki-url http://localhost:3100 --count 50"
  echo ""
  echo "    2. Watch detection logs:"
  echo "       kubectl logs -n $NAMESPACE -l app=detection-engine -f"
  echo ""
  echo "    3. Check Alertmanager:"
  echo "       kubectl port-forward -n $MONITORING_NS svc/alertmanager 9093:9093 &"
  echo "       curl http://localhost:9093/api/v2/alerts"
  echo ""
  echo "    4. Tear down:"
  echo "       kind delete cluster --name $CLUSTER_NAME"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "Detection-as-Code — Sandbox Setup"
  echo ""

  for tool in kind kubectl helm; do install_tool "$tool"; done
  create_cluster
  install_loki
  install_alertmanager
  build_engine
  deploy_engine
  verify
}

main "$@"
