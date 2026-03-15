# detection-as-code

Kubernetes-native detection engine that auto-discovers and runs security detection modules against Loki log streams. Fires alerts to Alertmanager and Slack.

## Architecture

```
CloudTrail → Promtail/Fluentd → Loki
                                  ↓
                         Detection Engine (K8s Deployment)
                         Auto-discovers 60+ modules
                         Polls Loki every 60s
                                  ↓
                         Alertmanager → Slack / PagerDuty / Email
```

## How it works

1. **cloud-sec-blog** scrapes threat feeds, enriches with CloudTrail events, and syncs detection modules here via GitHub Actions
2. **This repo** holds the detection modules (`detections/`) and the engine (`engine/`) that runs them
3. On every push, CI builds a Docker image → pushes to GHCR → K8s pulls the latest image

## Detection modules

Each module implements a standard interface:

```python
def logql_query() -> str:        # LogQL query for Loki
def detect(event: dict) -> bool: # Does this event match?
def title(event: dict) -> str:   # Alert title
def severity(event: dict) -> str: # critical/high/medium/low
def runbook(event: dict) -> str:  # Remediation steps
def metadata() -> dict:           # Module metadata
```

Modules are organized by category:

```
detections/
├── auth/          # IAM, credential, login detections
├── network/       # VPC, security group, network detections
├── data/          # S3, KMS, data access detections
└── cloudtrail/    # CloudTrail-specific event detections
```

## Quick start

### Sandbox (local testing)

```bash
# Spin up a kind cluster with Loki + Alertmanager + engine
./sandbox/setup.sh

# Inject test CloudTrail events
kubectl port-forward -n monitoring svc/loki 3100:3100 &
python sandbox/inject_cloudtrail.py --count 50

# Watch detections fire
kubectl logs -n detections -l app=detection-engine -f
```

### Production (Helm)

```bash
helm upgrade --install detection-engine ./helm \
  --set loki.url=http://your-loki:3100 \
  --set alertmanager.url=http://your-alertmanager:9093/api/v1/alerts \
  --set image.tag=latest
```

### Manual K8s deploy

```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/detection-engine-deployment.yaml
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `LOKI_URL` | `http://loki:3100` | Loki query endpoint |
| `ALERTMANAGER_URL` | `http://alertmanager:9093/api/v1/alerts` | Alertmanager push endpoint |
| `SLACK_WEBHOOK_URL` | (empty) | Slack webhook for alerts |
| `POLL_INTERVAL` | `60` | Seconds between detection cycles |
| `LOOKBACK_MINUTES` | `5` | How far back to query Loki |
| `LOG_LEVEL` | `INFO` | Logging level |

## Connected repos

| Repo | Role |
|------|------|
| [cloud-sec-blog](https://github.com/jackiecloudsec/cloud-sec-blog) | Threat intel pipeline + web UI. Generates detection modules and syncs them here. |
| **detection-as-code** (this repo) | Detection module library + K8s engine runtime. |

## Development

```bash
pip install -r requirements.txt pytest pyyaml
PYTHONPATH=. pytest tests/ -v
```
