"""Fire alerts when detections trigger."""
import logging

logger = logging.getLogger(__name__)


async def fire_alert(detection, event: dict) -> None:
    """Send alert (log for now; can wire to Alertmanager/Slack later)."""
    title = getattr(detection, "title", lambda e: "Alert")(event)
    severity = getattr(detection, "severity", lambda e: "INFO")(event)
    runbook = getattr(detection, "runbook", lambda e: "")(event)
    name = getattr(detection, "name", "unknown")
    logger.warning(
        "ALERT [%s] %s - %s | runbook: %s",
        severity,
        name,
        title,
        runbook,
        extra={"event": event},
    )
    # TODO: HTTP POST to Alertmanager or Slack webhook
