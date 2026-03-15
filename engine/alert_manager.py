"""
Alert manager: fire alerts to Alertmanager, Slack, or log output.

Supports:
  - Alertmanager HTTP API (default)
  - Slack webhook
  - Log-only mode (fallback)
"""

import os
import json
import logging
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

ALERTMANAGER_URL = os.environ.get(
    "ALERTMANAGER_URL",
    "http://alertmanager.monitoring.svc:9093/api/v1/alerts",
)
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
GENERATOR_URL = os.environ.get(
    "GENERATOR_URL",
    "https://cloud-sec-blog.onrender.com/intel/",
)


def _build_alert(detection, event: dict) -> dict:
    """Build an Alertmanager-compatible alert payload."""
    det_id = ""
    det_name = ""
    category = "unknown"

    if hasattr(detection, "metadata"):
        try:
            meta = detection.metadata()
            det_id = meta.get("id", "")
            det_name = meta.get("name", "")
            category = meta.get("category", "unknown")
        except Exception:
            pass

    if not det_name:
        det_name = getattr(detection, "DETECTION_NAME", getattr(detection, "name", "unknown"))
    if not det_id:
        det_id = getattr(detection, "DETECTION_ID", det_name)

    title_fn = getattr(detection, "title", lambda e: det_name)
    severity_fn = getattr(detection, "severity", lambda e: "medium")
    runbook_fn = getattr(detection, "runbook", lambda e: "")

    return {
        "labels": {
            "alertname": det_name[:128],
            "severity": severity_fn(event),
            "detection_id": det_id,
            "category": category,
            "source": "detection-as-code",
        },
        "annotations": {
            "title": title_fn(event),
            "runbook": runbook_fn(event),
            "event_name": event.get("eventName", ""),
            "source_ip": event.get("sourceIPAddress", ""),
            "user_arn": event.get("userIdentity", {}).get("arn", ""),
            "aws_region": event.get("awsRegion", ""),
        },
        "startsAt": datetime.now(timezone.utc).isoformat(),
        "generatorURL": f"{GENERATOR_URL}{det_id}",
    }


async def _send_alertmanager(alert: dict) -> bool:
    """POST alert to Alertmanager."""
    if not ALERTMANAGER_URL:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                ALERTMANAGER_URL,
                json=[alert],
                timeout=10.0,
            )
            if resp.status_code < 300:
                return True
            logger.warning("Alertmanager returned %d: %s", resp.status_code, resp.text[:200])
    except httpx.ConnectError:
        logger.debug("Alertmanager not reachable at %s", ALERTMANAGER_URL)
    except Exception as e:
        logger.warning("Alertmanager error: %s", e)
    return False


async def _send_slack(alert: dict) -> bool:
    """POST alert to Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        return False
    try:
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        text = (
            f":rotating_light: *{annotations.get('title', 'Detection Alert')}*\n"
            f"Severity: `{labels.get('severity', '?')}` | "
            f"Category: `{labels.get('category', '?')}`\n"
            f"Event: `{annotations.get('event_name', '?')}` from `{annotations.get('source_ip', '?')}`\n"
            f"User: `{annotations.get('user_arn', '?')}`\n"
            f"<{alert.get('generatorURL', '')}|View in cloud-sec-blog>"
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                SLACK_WEBHOOK_URL,
                json={"text": text},
                timeout=10.0,
            )
            return resp.status_code < 300
    except Exception as e:
        logger.warning("Slack error: %s", e)
    return False


async def fire_alert(detection, event: dict) -> None:
    """Fire alert to all configured destinations."""
    alert = _build_alert(detection, event)
    title = alert["annotations"].get("title", "Alert")
    severity = alert["labels"].get("severity", "?")

    # Always log
    logger.warning(
        "ALERT [%s] %s — %s from %s",
        severity.upper(),
        title,
        event.get("eventName", "?"),
        event.get("sourceIPAddress", "?"),
    )

    # Send to configured destinations
    sent_am = await _send_alertmanager(alert)
    sent_slack = await _send_slack(alert)

    if not sent_am and not sent_slack:
        logger.debug("Alert logged only (no Alertmanager or Slack configured)")
