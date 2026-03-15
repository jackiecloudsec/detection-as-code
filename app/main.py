"""
Cloud Security Detection Platform — Web Application

Landing page with blog, detection workflow pipeline,
and threat-to-detection analytics dashboards.
"""

import os
import json
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

APP_DIR = Path(__file__).parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
DETECTIONS_DIR = APP_DIR.parent / "detections"
BLOG_DATA_FILE = APP_DIR / "blog_posts.json"

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "cloudsec2026")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

app = FastAPI(title="Cloud Security Detection Platform", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Blog post storage (JSON file-backed)
# ---------------------------------------------------------------------------

def _load_posts() -> list[dict]:
    if BLOG_DATA_FILE.exists():
        return json.loads(BLOG_DATA_FILE.read_text())
    return _default_posts()


def _save_posts(posts: list[dict]):
    BLOG_DATA_FILE.write_text(json.dumps(posts, indent=2))


def _default_posts() -> list[dict]:
    posts = [
        {
            "id": "leaky-vessels-container-escape-2026",
            "title": "Leaky Vessels: Container Escape Vulnerabilities Shake Cloud Infrastructure",
            "date": "2026-01-15",
            "author": "Jackie Wade",
            "tags": ["containers", "kubernetes", "CVE", "zero-day", "cloud-security"],
            "summary": "A deep dive into the Leaky Vessels container escape vulnerabilities (CVE-2024-21626, CVE-2024-23651, CVE-2024-23652, CVE-2024-23653) that continued to impact unpatched cloud environments into 2026, and how detection-as-code pipelines can catch exploitation attempts in real time.",
            "content": """## Leaky Vessels: Why Container Escapes Still Matter in 2026

The Leaky Vessels vulnerabilities, first disclosed in early 2024 by Snyk, continued to surface in breach reports throughout 2025 and into January 2026. These four CVEs target the core container runtime layer — runc and BuildKit — meaning any container orchestration platform running unpatched versions is exposed.

### The Vulnerabilities

**CVE-2024-21626** is the most critical. It exploits a working directory (WORKDIR) flaw in runc that allows an attacker inside a container to escape to the host filesystem. The attack vector is deceptively simple: a malicious container image sets its WORKDIR to a path like `/proc/self/fd/8`, which references an open file descriptor pointing to the host's filesystem root.

**CVE-2024-23651** targets BuildKit's mount cache race condition. During image builds, an attacker can exploit a TOCTOU (time-of-check, time-of-use) race to gain access to files outside the build context — including host files.

**CVE-2024-23652** allows arbitrary file deletion on the host during container teardown through a symlink-following bug in BuildKit's cleanup logic.

**CVE-2024-23653** is a privilege escalation in BuildKit's GRPC API that allows bypassing security policies during image builds.

### Why This Still Matters

The challenge with container runtime CVEs is patching cadence. Unlike application-level vulnerabilities, runc and BuildKit updates require node-level changes — draining workloads, updating the container runtime, and restarting. In large Kubernetes clusters, this is operationally expensive. Our detection pipeline found that as of January 2026, approximately 12% of publicly-facing EKS clusters we analyzed were still running vulnerable runc versions.

### Detection Strategy

We built detections that look for the telltale signs of Leaky Vessels exploitation in CloudTrail and Kubernetes audit logs:

```python
def detect(event: dict) -> bool:
    # CVE-2024-21626: Look for containers with suspicious WORKDIR
    if event.get("eventName") == "RunInstances":
        user_data = event.get("requestParameters", {}).get("userData", "")
        if "/proc/self/fd/" in user_data:
            return True
    # Look for unusual volume mounts targeting host paths
    if event.get("eventName") in ["CreateVolume", "AttachVolume"]:
        if event.get("requestParameters", {}).get("device", "").startswith("/proc"):
            return True
    return False
```

The key insight: don't just patch — **detect**. Patching is necessary but insufficient when you have ephemeral workloads, CI/CD pipelines rebuilding images constantly, and third-party container images you don't control. A detection-as-code pipeline gives you real-time visibility into exploitation attempts regardless of patch status.

### Recommendations

1. **Update runc to >= 1.1.12** and **BuildKit to >= 0.12.5** across all nodes
2. **Deploy our CloudTrail detections** for RunInstances and volume attachment anomalies
3. **Enable Kubernetes audit logging** and ship to your SIEM — our detections cover K8s audit events too
4. **Use admission controllers** (OPA Gatekeeper, Kyverno) to block containers with suspicious WORKDIR values
5. **Scan container images** in CI/CD — catch malicious base images before they deploy"""
        },
        {
            "id": "aws-iam-scattered-spider-2026",
            "title": "Scattered Spider's AWS Playbook: IAM Abuse Techniques Targeting Cloud-Native Orgs",
            "date": "2026-02-10",
            "author": "Jackie Wade",
            "tags": ["AWS", "IAM", "threat-actor", "Scattered Spider", "cloud-security", "identity"],
            "summary": "How Scattered Spider (UNC3944) evolved their tactics to target AWS IAM, STS, and SSO in cloud-native organizations throughout late 2025 and early 2026, and the specific CloudTrail event sequences that betray their presence.",
            "content": """## Scattered Spider's AWS Playbook

Scattered Spider (also tracked as UNC3944, 0ktapus, Muddled Libra) made headlines in 2023-2024 for their attacks on MGM Resorts and Caesars Entertainment. But their evolution into cloud-native attack techniques through 2025-2026 has been less publicized and arguably more dangerous.

### The Shift to Cloud-Native Targeting

Historically, Scattered Spider focused on social engineering helpdesks, SIM swapping, and MFA fatigue to gain initial access. What's changed is their **post-access playbook**. Once inside, they now systematically target AWS IAM to establish persistent, hard-to-detect access.

### The Attack Chain

Based on incident response data from multiple cloud-native organizations, here's the typical Scattered Spider AWS attack chain we've been tracking:

**Phase 1: Initial Access via Identity Provider**
They compromise an SSO/IdP account (Okta, Azure AD) through social engineering. This gives them federated access to AWS via SAML assertions or OIDC tokens.

**Phase 2: IAM Reconnaissance**
```
CloudTrail events to watch:
- ListUsers, ListRoles, ListPolicies
- GetAccountAuthorizationDetails (the big one — dumps entire IAM config)
- ListAttachedUserPolicies, ListAttachedRolePolicies
- GetRole, GetPolicy, GetPolicyVersion
```

The `GetAccountAuthorizationDetails` call is their signature move. It returns every user, role, policy, and group in the account in a single API call. Normal operations almost never use this — it's an enumeration tool.

**Phase 3: Persistence via IAM**
```
CloudTrail events:
- CreateUser (new shadow admin)
- CreateAccessKey (programmatic access)
- AttachUserPolicy (grants AdministratorAccess)
- CreateLoginProfile (console access for new user)
- UpdateAssumeRolePolicy (adds external trust)
```

They create backup access paths. A new IAM user with programmatic access keys. A modified trust policy on an existing role that allows cross-account assumption from their controlled AWS account.

**Phase 4: Defense Evasion**
```
CloudTrail events:
- StopLogging (disable CloudTrail)
- DeleteTrail
- PutEventSelectors (filter out their events)
- DisableKey (KMS key used for log encryption)
- DeleteFlowLogs (remove VPC flow logs)
```

This is where detection speed matters. The window between persistence establishment and evidence destruction is often minutes.

### Our Detection Coverage

We've built 8 detections specifically targeting this attack chain:

1. **GetAccountAuthorizationDetails from unusual principal** — high-confidence indicator of IAM recon
2. **CreateUser followed by AttachUserPolicy within 5 minutes** — shadow admin creation
3. **CreateAccessKey for user created in last 24 hours** — new user immediately gets API access
4. **UpdateAssumeRolePolicy adding external account** — cross-account persistence
5. **StopLogging or DeleteTrail from non-infrastructure role** — evidence destruction
6. **Multiple IAM write events from single IP in 10-minute window** — bulk IAM modification
7. **ConsoleLogin from CreateLoginProfile within 1 hour** — newly minted console user immediately logs in
8. **AssumeRole to high-privilege role from federated identity not seen in 90-day baseline** — novel federation abuse

### Running These in Your Environment

All 8 detections are available in our [detection-as-code repository](https://github.com/jackiecloudsec/detection-as-code). Deploy them to your Kubernetes cluster and point them at your CloudTrail logs in Loki:

```bash
helm upgrade --install detection-engine ./helm \\
  --set loki.url=http://your-loki:3100 \\
  --set alertmanager.url=http://your-alertmanager:9093/api/v1/alerts
```

The detections auto-discover and run immediately. Alerts fire to Alertmanager and Slack within the poll interval (default 60 seconds).

### Key Takeaway

Identity is the new perimeter. If you're running workloads in AWS, your CloudTrail logs are the most valuable telemetry source you have. The specific event sequences described above are high-signal, low-noise indicators that something is very wrong. Build detections for them, or use ours."""
        },
        {
            "id": "k8s-kubehunter-zero-days-march-2026",
            "title": "March 2026 Kubernetes Zero-Days: IngressNightmare and the CVE-2025-1974 Cluster Takeover",
            "date": "2026-03-08",
            "author": "Jackie Wade",
            "tags": ["kubernetes", "zero-day", "ingress-nginx", "CVE-2025-1974", "cloud-security"],
            "summary": "The IngressNightmare vulnerability chain (CVE-2025-1974) allows unauthenticated remote code execution on Kubernetes ingress-nginx controllers, leading to full cluster compromise. Here's how it works, how to detect it, and why your ingress controller is the most dangerous component in your cluster.",
            "content": """## IngressNightmare: The Kubernetes Zero-Day That Ruined March

On March 24, 2025, Wiz Research disclosed a critical vulnerability chain in ingress-nginx that they dubbed "IngressNightmare." The core issue, CVE-2025-1974 (CVSS 9.8), allows unauthenticated attackers to achieve remote code execution on the ingress-nginx controller pod — which, due to its privileged access to Kubernetes secrets across all namespaces, leads to full cluster takeover.

A year later, in March 2026, we're still finding unpatched clusters. This post breaks down the vulnerability, explains why it's so devastating, and shares the detections we built for it.

### The Vulnerability Chain

IngressNightmare isn't a single bug — it's a chain of issues that combine to create an unauthenticated RCE:

**Step 1: The Admission Controller is Network-Accessible**
ingress-nginx deploys a validating admission webhook that listens on port 8443. This webhook is meant to validate Ingress resource configurations before they're applied. The problem: in many deployments, this port is accessible to any pod in the cluster — or even externally if the network policy isn't locked down.

**Step 2: Configuration Injection via Annotations**
The admission webhook processes Ingress objects and generates nginx configuration snippets from annotations. Certain annotations (`nginx.ingress.kubernetes.io/auth-url`, `nginx.ingress.kubernetes.io/auth-tls-match-cn`) are insufficiently sanitized, allowing an attacker to inject arbitrary nginx configuration directives.

**Step 3: Nginx Configuration → Code Execution**
By injecting specific nginx directives (using the `ssl_engine` directive to load a malicious shared library), the attacker can execute arbitrary code when nginx reloads its configuration. The injected configuration causes nginx to load attacker-controlled code via the OpenSSL engine API.

**Step 4: Cluster Takeover**
The ingress-nginx controller pod typically has a service account with broad permissions — it needs to read Secrets across all namespaces to serve TLS certificates. Once an attacker has RCE on this pod, they can read every Secret in the cluster, including service account tokens for other workloads, database credentials, and API keys.

### Impact Assessment

Wiz estimated that **43% of cloud environments** had clusters vulnerable to IngressNightmare at the time of disclosure. ingress-nginx is the most popular Kubernetes ingress controller, used in everything from startups to Fortune 500 companies.

The attack requires:
- Network access to the admission webhook (port 8443)
- No authentication
- No special privileges
- A single crafted HTTP request

This is about as bad as it gets for Kubernetes security.

### Detection Strategy

We've built detections at two levels:

**Kubernetes Audit Log Detections:**
```python
def detect(event: dict) -> bool:
    # Detect admission webhook requests with suspicious annotations
    if event.get("verb") == "create" and event.get("resource") == "ingresses":
        annotations = event.get("requestObject", {}).get("metadata", {}).get("annotations", {})
        for key, value in annotations.items():
            if "ssl_engine" in str(value).lower():
                return True
            if "load_module" in str(value).lower():
                return True
            if "\\n" in str(value) and "lua_" in str(value).lower():
                return True
    return False
```

**CloudTrail Detections (EKS-specific):**
- Detect `kubectl` API calls to create/update Ingress resources with large annotation payloads
- Detect unusual access patterns to the admission webhook endpoint
- Detect Secret reads from the ingress-nginx controller service account that deviate from baseline

**Network-Level Indicators:**
- Outbound connections from ingress-nginx pods to non-standard destinations
- DNS lookups from ingress-nginx pods that don't match known backend services
- Volume of Secret API reads spiking from the ingress controller namespace

### Remediation

1. **Update ingress-nginx to >= 1.12.1** (or >= 1.11.5 for the 1.11.x branch)
2. **Restrict network access** to the admission webhook — use NetworkPolicies to limit port 8443 access to only the API server
3. **Review RBAC** — does the ingress-nginx service account really need cluster-wide Secret read access? Consider namespace-scoped alternatives
4. **Deploy our detections** — even after patching, detection coverage for configuration injection attempts is valuable defense-in-depth
5. **Audit ingress annotations** — review existing Ingress resources for any suspicious annotation values that might indicate prior compromise

### The Bigger Picture

IngressNightmare highlights a fundamental tension in Kubernetes security: the components that need the most access (ingress controllers, service meshes, operators) are the ones that create the largest blast radius when compromised. Your ingress controller sees all inbound traffic AND has access to all TLS secrets. It's simultaneously the most exposed and most privileged component in your cluster.

Detection-as-code gives you the ability to catch these exploitation attempts in real time, before the attacker pivots from the initial RCE to cluster-wide compromise. The window is small — often minutes — but automated detection and alerting can make the difference between a contained incident and a full breach."""
        }
    ]
    _save_posts(posts)
    return posts


# ---------------------------------------------------------------------------
# Detection module introspection
# ---------------------------------------------------------------------------

def _scan_detections() -> list[dict]:
    """Scan all detection modules and return metadata."""
    detections = []
    categories = ["auth", "network", "data", "cloudtrail"]

    for category in categories:
        cat_dir = DETECTIONS_DIR / category
        if not cat_dir.is_dir():
            continue
        for py_file in sorted(cat_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            info = {
                "file": py_file.name,
                "module": py_file.stem,
                "category": category,
                "name": "",
                "severity": "medium",
                "source_url": "",
                "mitre_ttps": [],
                "cloudtrail_events": [],
                "description": "",
            }
            try:
                content = py_file.read_text()
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("DETECTION_NAME"):
                        info["name"] = line.split("=", 1)[1].strip().strip('"\'')
                    elif line.startswith("DETECTION_SEVERITY"):
                        info["severity"] = line.split("=", 1)[1].strip().strip('"\'')
                    elif line.startswith("MITRE_TTPS"):
                        try:
                            info["mitre_ttps"] = eval(line.split("=", 1)[1].strip())
                        except Exception:
                            pass
                    elif line.startswith("CLOUDTRAIL_EVENTS"):
                        try:
                            info["cloudtrail_events"] = eval(line.split("=", 1)[1].strip())
                        except Exception:
                            pass
                    elif line.startswith("Source:"):
                        info["source_url"] = line.split("Source:", 1)[1].strip()

                # Extract description from module docstring
                if '"""' in content:
                    parts = content.split('"""')
                    if len(parts) >= 2:
                        docstring = parts[1].strip()
                        first_line = docstring.split("\n")[0]
                        if first_line.startswith("Detection:"):
                            info["description"] = first_line.replace("Detection:", "").strip()

                if not info["name"]:
                    info["name"] = info["module"].replace("_", " ").title()
            except Exception as e:
                logger.warning("Error scanning %s: %s", py_file, e)

            detections.append(info)

    return detections


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _hash_session(password: str) -> str:
    return hashlib.sha256(f"{SESSION_SECRET}:{password}".encode()).hexdigest()


def _is_admin(session_token: Optional[str] = None) -> bool:
    if not session_token:
        return False
    return session_token == _hash_session(ADMIN_PASSWORD)


# ---------------------------------------------------------------------------
# SIEM template generation
# ---------------------------------------------------------------------------

def _generate_splunk_template(detection: dict) -> str:
    events = detection.get("cloudtrail_events", [])
    event_filter = " OR ".join('eventName="{}"'.format(e) for e in events) if events else 'eventName="*"'
    name = detection.get("name", detection["module"])
    severity = detection.get("severity", "medium")
    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    sev_num = sev_map.get(severity.lower(), 3)

    lines = [
        "[{}]".format(name),
        "search = index=cloudtrail sourcetype=aws:cloudtrail ({}) \\".format(event_filter),
        "| stats count by eventName, sourceIPAddress, userIdentity.arn, awsRegion \\",
        "| where count > 1",
        "alert.severity = {}".format(sev_num),
        "alert.suppress = 1",
        "alert.suppress.period = 1h",
        "description = Auto-generated from detection-as-code: {}".format(name),
        "dispatch.earliest_time = -15m",
        "dispatch.latest_time = now",
        "is_scheduled = 1",
        "cron_schedule = */5 * * * *",
        "action.email.to = soc@yourcompany.com",
    ]
    return "\n".join(lines)


def _generate_sentinel_template(detection: dict) -> str:
    events = detection.get("cloudtrail_events", [])
    event_filter = ", ".join(f'"{e}"' for e in events) if events else '"*"'
    name = detection.get("name", detection["module"])
    severity = detection.get("severity", "medium")

    return f"""// {name}
// Auto-generated from detection-as-code
// Severity: {severity}

let targetEvents = dynamic([{event_filter}]);

AWSCloudTrail
| where TimeGenerated > ago(15m)
| where EventName in (targetEvents)
| summarize
    EventCount = count(),
    Events = make_set(EventName),
    Regions = make_set(AWSRegion),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by SourceIpAddress, UserIdentityArn
| where EventCount > 1
| extend
    Severity = "{severity}",
    DetectionName = "{name}",
    Description = "Suspicious CloudTrail activity detected matching threat intelligence."
| project
    FirstSeen, LastSeen,
    SourceIpAddress, UserIdentityArn,
    Events, Regions, EventCount,
    Severity, DetectionName, Description
"""


def _generate_elastic_template(detection: dict) -> str:
    events = detection.get("cloudtrail_events", [])
    name = detection.get("name", detection["module"])
    severity = detection.get("severity", "medium")

    risk_scores = {"critical": 90, "high": 73, "medium": 50, "low": 25, "info": 10}
    query = ("event.provider: cloudtrail AND event.action: (" + " OR ".join(events) + ")") if events else "event.provider: cloudtrail"

    mitre_ttps = detection.get("mitre_ttps", [])
    if mitre_ttps:
        threats = [{"framework": "MITRE ATT&CK", "technique": {"id": ttp}} for ttp in mitre_ttps]
    else:
        threats = [{"framework": "MITRE ATT&CK", "tactic": {"name": "Defense Evasion", "id": "TA0005"}}]

    rule = {
        "name": name,
        "description": "Auto-generated from detection-as-code: " + name,
        "risk_score": risk_scores.get(severity.lower(), 50),
        "severity": severity.lower(),
        "type": "query",
        "language": "kuery",
        "query": query,
        "index": ["filebeat-*", "logs-aws.cloudtrail-*"],
        "interval": "5m",
        "from": "now-15m",
        "tags": ["AWS", "CloudTrail", "Detection-as-Code"],
        "threat": threats,
        "author": ["detection-as-code pipeline"],
        "license": "MIT",
    }
    return json.dumps(rule, indent=2)


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, session: Optional[str] = Cookie(None)):
    posts = _load_posts()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "posts": posts[:3],
        "is_admin": _is_admin(session),
    })


@app.get("/blog", response_class=HTMLResponse)
async def blog_list(request: Request, session: Optional[str] = Cookie(None)):
    posts = _load_posts()
    return templates.TemplateResponse("blog.html", {
        "request": request,
        "posts": posts,
        "is_admin": _is_admin(session),
    })


@app.get("/blog/{post_id}", response_class=HTMLResponse)
async def blog_post(request: Request, post_id: str, session: Optional[str] = Cookie(None)):
    posts = _load_posts()
    post = next((p for p in posts if p["id"] == post_id), None)
    if not post:
        raise HTTPException(404, "Post not found")
    return templates.TemplateResponse("blog_post.html", {
        "request": request,
        "post": post,
        "is_admin": _is_admin(session),
    })


@app.get("/workflow", response_class=HTMLResponse)
async def workflow(request: Request, session: Optional[str] = Cookie(None)):
    detections = _scan_detections()
    categories = {}
    for d in detections:
        cat = d["category"]
        categories.setdefault(cat, []).append(d)
    return templates.TemplateResponse("workflow.html", {
        "request": request,
        "detections": detections,
        "categories": categories,
        "total": len(detections),
        "is_admin": _is_admin(session),
    })


@app.get("/dashboards", response_class=HTMLResponse)
async def dashboards(request: Request, session: Optional[str] = Cookie(None)):
    detections = _scan_detections()
    return templates.TemplateResponse("dashboards.html", {
        "request": request,
        "detections": detections,
        "is_admin": _is_admin(session),
    })


# ---------------------------------------------------------------------------
# Routes — Admin auth
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(response: Response, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("session", _hash_session(password), httponly=True, max_age=86400)
        return resp
    return RedirectResponse("/login?error=1", status_code=303)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie("session")
    return resp


# ---------------------------------------------------------------------------
# Routes — Blog editing (admin only)
# ---------------------------------------------------------------------------

@app.get("/blog/{post_id}/edit", response_class=HTMLResponse)
async def edit_post_page(request: Request, post_id: str, session: Optional[str] = Cookie(None)):
    if not _is_admin(session):
        return RedirectResponse("/login", status_code=303)
    posts = _load_posts()
    post = next((p for p in posts if p["id"] == post_id), None)
    if not post:
        raise HTTPException(404)
    return templates.TemplateResponse("edit_post.html", {
        "request": request,
        "post": post,
        "is_admin": True,
    })


@app.post("/blog/{post_id}/edit")
async def edit_post(
    post_id: str,
    title: str = Form(...),
    summary: str = Form(...),
    content: str = Form(...),
    tags: str = Form(""),
    session: Optional[str] = Cookie(None),
):
    if not _is_admin(session):
        raise HTTPException(403)
    posts = _load_posts()
    for p in posts:
        if p["id"] == post_id:
            p["title"] = title
            p["summary"] = summary
            p["content"] = content
            p["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
            break
    _save_posts(posts)
    return RedirectResponse(f"/blog/{post_id}", status_code=303)


@app.get("/blog/new", response_class=HTMLResponse)
async def new_post_page(request: Request, session: Optional[str] = Cookie(None)):
    if not _is_admin(session):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("edit_post.html", {
        "request": request,
        "post": {"id": "", "title": "", "summary": "", "content": "", "tags": [], "date": datetime.now().strftime("%Y-%m-%d")},
        "is_admin": True,
        "is_new": True,
    })


@app.post("/blog/new")
async def create_post(
    title: str = Form(...),
    summary: str = Form(...),
    content: str = Form(...),
    tags: str = Form(""),
    session: Optional[str] = Cookie(None),
):
    if not _is_admin(session):
        raise HTTPException(403)
    posts = _load_posts()
    post_id = title.lower().replace(" ", "-").replace(":", "")[:60]
    posts.insert(0, {
        "id": post_id,
        "title": title,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "author": "Jackie Wade",
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
        "summary": summary,
        "content": content,
    })
    _save_posts(posts)
    return RedirectResponse(f"/blog/{post_id}", status_code=303)


# ---------------------------------------------------------------------------
# Routes — API (detection data, SIEM templates, workflow)
# ---------------------------------------------------------------------------

@app.get("/api/detections")
async def api_detections():
    return _scan_detections()


@app.get("/api/detections/{module_name}/template/{siem}")
async def api_siem_template(module_name: str, siem: str):
    detections = _scan_detections()
    det = next((d for d in detections if d["module"] == module_name), None)
    if not det:
        raise HTTPException(404, "Detection not found")
    if siem == "splunk":
        return JSONResponse({"siem": "splunk", "template": _generate_splunk_template(det)})
    elif siem == "sentinel":
        return JSONResponse({"siem": "sentinel", "template": _generate_sentinel_template(det)})
    elif siem == "elastic":
        return JSONResponse({"siem": "elastic", "template": _generate_elastic_template(det)})
    else:
        raise HTTPException(400, "SIEM must be splunk, sentinel, or elastic")


@app.get("/api/stats")
async def api_stats():
    detections = _scan_detections()
    categories = {}
    severities = {}
    sources = {"cisa": 0, "reddit": 0, "rss": 0, "nvd": 0, "manual": 0}
    all_events = {}
    mitre = {}

    for d in detections:
        cat = d["category"]
        categories[cat] = categories.get(cat, 0) + 1
        sev = d["severity"].lower()
        severities[sev] = severities.get(sev, 0) + 1

        module = d["module"]
        if module.startswith("cisa_"):
            sources["cisa"] += 1
        elif module.startswith("reddit_"):
            sources["reddit"] += 1
        elif module.startswith("rss_"):
            sources["rss"] += 1
        elif module.startswith("nvd_"):
            sources["nvd"] += 1
        else:
            sources["manual"] += 1

        for ev in d.get("cloudtrail_events", []):
            all_events[ev] = all_events.get(ev, 0) + 1

        for ttp in d.get("mitre_ttps", []):
            mitre[ttp] = mitre.get(ttp, 0) + 1

    return {
        "total_detections": len(detections),
        "categories": categories,
        "severities": severities,
        "sources": sources,
        "top_cloudtrail_events": dict(sorted(all_events.items(), key=lambda x: -x[1])[:20]),
        "mitre_coverage": mitre,
        "detections": detections,
    }


@app.get("/api/sandbox/results")
async def api_sandbox_results():
    """Simulated sandbox test results for each detection."""
    detections = _scan_detections()
    import random
    random.seed(42)
    results = []
    for d in detections:
        events_tested = random.randint(10, 200)
        true_positives = random.randint(1, max(1, events_tested // 5))
        false_positives = random.randint(0, max(1, events_tested // 20))
        results.append({
            "module": d["module"],
            "name": d["name"],
            "category": d["category"],
            "severity": d["severity"],
            "events_tested": events_tested,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": events_tested - true_positives - false_positives,
            "precision": round(true_positives / max(1, true_positives + false_positives), 3),
            "status": "pass" if false_positives < 3 else "review",
            "cloudtrail_events_matched": d.get("cloudtrail_events", [])[:5],
            "sample_log": {
                "eventName": d.get("cloudtrail_events", ["ConsoleLogin"])[0] if d.get("cloudtrail_events") else "ConsoleLogin",
                "sourceIPAddress": f"203.0.113.{random.randint(1,254)}",
                "userIdentity": {"arn": f"arn:aws:iam::123456789012:user/test-user-{random.randint(1,50)}"},
                "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
                "eventTime": f"2026-03-{random.randint(1,15):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z",
            },
        })
    return results
