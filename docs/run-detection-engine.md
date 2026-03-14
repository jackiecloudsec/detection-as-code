# Get the detection engine running

Run these in order from the repo root. Use the same namespace everywhere (here: `default`).

## 1. Cluster and Loki

```bash
# Start minikube (if not running)
minikube start --driver=docker --cpus=4 --memory=6g

# Install Loki stack once (if not already)
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm install loki-stack grafana/loki-stack \
  --namespace monitoring \
  --create-namespace \
  --set grafana.enabled=true \
  --set promtail.enabled=true \
  --set loki.enabled=true
```

## 2. GHCR pull secret (for private image)

Create a GitHub PAT with **read:packages**, then:

```bash
kubectl create secret docker-registry ghcr-pull-secret \
  --docker-server=ghcr.io \
  --docker-username=jackiecloudsec \
  --docker-password=YOUR_GITHUB_PAT \
  --namespace=default
```

(Or make the package public at https://github.com/jackiecloudsec/detection-as-code/pkgs/container/detection-engine and skip this step; then remove `imagePullSecrets` from the deployment if you prefer.)

## 3. Deploy detection engine

**Option A – raw manifests**

```bash
cd /Users/jackiewade/Desktop/repositories/detection-as-code
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/detection-engine-deployment.yaml
```

**Option B – Helm**

```bash
cd /Users/jackiewade/Desktop/repositories/detection-as-code
helm upgrade --install detection-engine ./helm -f helm/values-local.yaml --namespace default
```

## 4. Verify

```bash
kubectl get pods -l app=detection-engine
kubectl logs -f deployment/detection-engine
```

Pod should be `Running` and logs show the engine looping (and possibly Loki connection messages). If you see `ImagePullBackOff`, the secret is missing or wrong; if you see connection errors to Loki, check that the Loki stack is up in `monitoring`.

## 5. Restart after image or config change

```bash
kubectl delete pod -l app=detection-engine
# Or with Helm:
# helm upgrade detection-engine ./helm -f helm/values-local.yaml
# kubectl delete pod -l app=detection-engine
```
