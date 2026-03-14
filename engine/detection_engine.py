"""Detection engine: query Loki, run detections, fire alerts."""
import os
import asyncio
import logging
import httpx
from engine.log_parser import parse_log_line
from engine.alert_manager import fire_alert
from detections.auth import brute_force, failed_login, impossible_travel
from detections.network import port_scan

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")

DETECTIONS = [
    brute_force,
    failed_login,
    impossible_travel,
    port_scan,
]


async def query_loki(logql: str, minutes: int = 5) -> dict:
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


async def run_detections() -> None:
    while True:
        for detection in DETECTIONS:
            try:
                logql = detection.logql_query()
                results = await query_loki(logql)
                for stream in results.get("data", {}).get("result", []):
                    for _, line in stream.get("values", []):
                        event = parse_log_line(line)
                        if event and detection.detect(event):
                            await fire_alert(detection, event)
            except Exception as e:
                logging.getLogger(__name__).exception(
                    "Detection %s failed: %s", getattr(detection, "name", detection), e
                )
        await asyncio.sleep(60)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_detections())


if __name__ == "__main__":
    main()
