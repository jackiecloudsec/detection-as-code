#!/usr/bin/env python3
"""Run all detections against sample log lines (no Loki). Use this to test your detections."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.log_parser import parse_log_line
from engine.alert_manager import fire_alert
from detections.auth import brute_force, failed_login, impossible_travel
from detections.network import port_scan

DETECTIONS = [brute_force, failed_login, impossible_travel, port_scan]

# Sample log lines (same format Loki would return)
SAMPLE_LOGS = [
    '{"source_ip": "10.0.0.1", "failure_count": 7, "msg": "authentication failure"}',
    '{"source_ip": "10.0.0.2", "failed_count": 4, "msg": "failed login"}',
    '{"source_ip": "10.0.0.3", "unique_ports": 15, "msg": "connection"}',
]

async def main():
    print("Running detections on sample logs (no Loki)...\n")
    for detection in DETECTIONS:
        print(f"Detection: {getattr(detection, 'name', detection)}")
        for line in SAMPLE_LOGS:
            event = parse_log_line(line)
            if event and detection.detect(event):
                await fire_alert(detection, event)
        print()
    print("Done.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
