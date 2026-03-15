"""
Detection engine: auto-discover modules, query Loki, run detections, fire alerts.

Discovers all detection modules in detections/ (auth, network, data, cloudtrail)
that implement the standard interface: logql_query(), detect(), title(), severity(), runbook().

Runs as a continuous loop polling Loki every POLL_INTERVAL seconds.
"""

import os
import asyncio
import logging
import importlib
import pkgutil
from pathlib import Path

import httpx

from engine.log_parser import parse_log_line
from engine.alert_manager import fire_alert

logger = logging.getLogger(__name__)

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "5"))


def discover_detections() -> list:
    """
    Auto-discover all detection modules under detections/.

    A valid detection module must have at least:
      - logql_query() -> str
      - detect(event) -> bool

    Returns a list of module objects.
    """
    detections_dir = Path(__file__).parent.parent / "detections"
    modules = []

    categories = ["auth", "network", "data", "cloudtrail"]

    for category in categories:
        category_dir = detections_dir / category
        if not category_dir.is_dir():
            continue

        pkg_name = f"detections.{category}"
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError as e:
            logger.warning("Could not import %s: %s", pkg_name, e)
            continue

        for importer, mod_name, is_pkg in pkgutil.iter_modules([str(category_dir)]):
            if mod_name.startswith("_"):
                continue
            full_name = f"{pkg_name}.{mod_name}"
            try:
                mod = importlib.import_module(full_name)
                # Validate required interface
                if hasattr(mod, "logql_query") and hasattr(mod, "detect"):
                    modules.append(mod)
                    logger.debug("Loaded detection: %s", full_name)
                else:
                    logger.debug("Skipped %s (missing logql_query or detect)", full_name)
            except Exception as e:
                logger.warning("Failed to load %s: %s", full_name, e)

    return modules


async def query_loki(logql: str, minutes: int = None) -> dict:
    """Query Loki for recent log entries matching the LogQL query."""
    if minutes is None:
        minutes = LOOKBACK_MINUTES

    params = {
        "query": logql,
        "start": f"{minutes}m",
        "limit": 1000,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()


async def run_single_detection(detection, stats: dict) -> None:
    """Run a single detection module against Loki."""
    det_name = _detection_name(detection)
    try:
        logql = detection.logql_query()
        results = await query_loki(logql)

        events_checked = 0
        matches = 0

        for stream in results.get("data", {}).get("result", []):
            for _, line in stream.get("values", []):
                event = parse_log_line(line)
                if not event:
                    continue
                events_checked += 1
                if detection.detect(event):
                    matches += 1
                    await fire_alert(detection, event)

        stats["events"] += events_checked
        stats["matches"] += matches

        if matches > 0:
            logger.info("%s: %d/%d events matched", det_name, matches, events_checked)

    except httpx.HTTPStatusError as e:
        logger.error("%s: Loki returned %s", det_name, e.response.status_code)
    except httpx.ConnectError:
        logger.error("%s: Cannot connect to Loki at %s", det_name, LOKI_URL)
    except Exception as e:
        logger.exception("%s failed: %s", det_name, e)


def _detection_name(detection) -> str:
    """Get a human-readable name for a detection module."""
    if hasattr(detection, "DETECTION_NAME"):
        return detection.DETECTION_NAME[:60]
    if hasattr(detection, "metadata"):
        try:
            return detection.metadata().get("name", detection.__name__)[:60]
        except Exception:
            pass
    return getattr(detection, "__name__", "unknown")


async def run_detections() -> None:
    """Main loop: discover detections, run them against Loki on a schedule."""
    detections = discover_detections()
    logger.info("Discovered %d detection modules", len(detections))

    for det in detections:
        name = _detection_name(det)
        category = getattr(det, "DETECTION_SEVERITY", "?")
        logger.info("  - %s [%s]", name, category)

    if not detections:
        logger.warning("No detections found. Check detections/ directory.")
        return

    cycle = 0
    while True:
        cycle += 1
        stats = {"events": 0, "matches": 0}

        # Run all detections concurrently
        tasks = [run_single_detection(det, stats) for det in detections]
        await asyncio.gather(*tasks)

        if cycle % 10 == 1 or stats["matches"] > 0:
            logger.info(
                "Cycle %d: %d detections, %d events checked, %d alerts fired",
                cycle, len(detections), stats["events"], stats["matches"],
            )

        await asyncio.sleep(POLL_INTERVAL)


def main() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info("Starting detection engine (Loki: %s, poll: %ds)", LOKI_URL, POLL_INTERVAL)
    asyncio.run(run_detections())


if __name__ == "__main__":
    main()
