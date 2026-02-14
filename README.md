# Detection as Code

Python detection engine that queries Loki for logs, runs detection functions, and fires alerts. Designed to run on minikube alongside Grafana + Loki stack.

## Stack

- **Loki** — log aggregation
- **Promtail** — log shipping to Loki
- **Grafana** — dashboards and alerting
- **Detection engine** — runs detections against Loki and fires alerts

## Local setup (minikube)

1. Start minikube and install Loki stack:

   ```bash
   minikube start --driver=docker --cpus=4 --memory=8g
   helm repo add grafana https://grafana.github.io/helm-charts
   helm repo update
   helm install loki-stack grafana/loki-stack \
     --namespace monitoring \
     --create-namespace \
     --set grafana.enabled=true \
     --set promtail.enabled=true \
     --set loki.enabled=true
   ```

2. Get Grafana password and port-forward:

   ```bash
   kubectl get secret --namespace monitoring loki-stack-grafana \
     -o jsonpath="{.data.admin-password}" | base64 --decode
   kubectl port-forward --namespace monitoring service/loki-stack-grafana 3000:80
   ```

   Open http://localhost:3000

3. Deploy the detection engine (after building and pushing the image):

   **Option A — Helm (recommended):**
   ```bash
   helm install detection-engine ./helm -f helm/values-local.yaml --namespace default --create-namespace
   # Upgrade after new image builds:
   helm upgrade detection-engine ./helm -f helm/values-local.yaml
   ```

   **Option B — Raw manifests:**
   ```bash
   kubectl apply -f k8s/configmap.yaml
   kubectl apply -f k8s/detection-engine-deployment.yaml
   ```

## Project structure

```
detection-as-code/
├── detections/        (expand here: add modules and register in engine)
│   ├── auth/          (brute_force, impossible_travel)
│   └── network/       (port_scan)
├── engine/            (Loki client, parser, alert manager)
├── k8s/               (Deployment, ConfigMap)
├── helm/              (Chart + values; use for deploy)
├── tests/
└── .github/workflows/ (test + deploy)
```

## Development

- Install: `pip install -r requirements.txt`
- Run tests: `PYTHONPATH=. pytest tests/ -v`
- Run engine locally (needs Loki): `LOKI_URL=http://localhost:3100 PYTHONPATH=. python -m engine.detection_engine`

## CI/CD

- Push to `main` runs tests and builds/pushes the Docker image to `ghcr.io/jackiecloudsec/detection-as-code/detection-engine`.
- Deploy with Helm: `helm upgrade --install detection-engine ./helm -f helm/values-local.yaml`.

## Expanding detection rules

Add new detection modules under `detections/` (e.g. `detections/endpoint/`, `detections/cloud/`). Each module should expose a detection object with: `logql_query()`, `detect(event)`, `title(event)`, `severity(event)`, `runbook(event)`. Register it in `engine/detection_engine.py` by appending to the `DETECTIONS` list. Add unit tests under `tests/` and run `PYTHONPATH=. pytest tests/ -v`.
