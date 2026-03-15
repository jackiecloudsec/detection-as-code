#!/usr/bin/env python3
"""
Inject sample CloudTrail events into Loki for testing detections.

Usage:
    python sandbox/inject_cloudtrail.py
    python sandbox/inject_cloudtrail.py --loki-url http://localhost:3100 --count 50
    python sandbox/inject_cloudtrail.py --events CreateUser,AttachUserPolicy --count 10
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen

SAMPLE_EVENTS = [
    "ConsoleLogin", "CreateUser", "CreateAccessKey", "AttachUserPolicy",
    "AttachRolePolicy", "AssumeRole", "PutBucketPolicy", "GetObject",
    "PutObject", "ListBuckets", "RunInstances", "AuthorizeSecurityGroupIngress",
    "StopLogging", "DeleteTrail", "CreateFunction", "GetSecretValue",
    "ScheduleKeyDeletion", "DisableKey", "PutRolePolicy", "CreateLoginProfile",
    "CopySnapshot", "PutBucketAcl", "DeleteObject", "CreateSecurityGroup",
]

SAMPLE_IPS = [
    "203.0.113.42", "198.51.100.7", "192.0.2.100",
    "10.0.0.15", "172.16.0.50", "45.33.32.156",
]

SAMPLE_ARNS = [
    "arn:aws:iam::123456789012:user/admin",
    "arn:aws:iam::123456789012:user/deploy-bot",
    "arn:aws:iam::123456789012:role/LambdaExecRole",
    "arn:aws:iam::123456789012:user/unknown-actor",
    "arn:aws:sts::123456789012:assumed-role/SuspiciousRole/session1",
]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

EVENT_SOURCES = {
    "ConsoleLogin": "signin.amazonaws.com",
    "CreateUser": "iam.amazonaws.com",
    "CreateAccessKey": "iam.amazonaws.com",
    "AttachUserPolicy": "iam.amazonaws.com",
    "AttachRolePolicy": "iam.amazonaws.com",
    "AssumeRole": "sts.amazonaws.com",
    "GetObject": "s3.amazonaws.com",
    "PutObject": "s3.amazonaws.com",
    "PutBucketPolicy": "s3.amazonaws.com",
    "RunInstances": "ec2.amazonaws.com",
    "StopLogging": "cloudtrail.amazonaws.com",
    "CreateFunction": "lambda.amazonaws.com",
    "GetSecretValue": "secretsmanager.amazonaws.com",
}


def generate_event(event_name: str = None) -> dict:
    if not event_name:
        event_name = random.choice(SAMPLE_EVENTS)

    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": random.choice(["IAMUser", "AssumedRole", "Root"]),
            "principalId": f"AIDA{random.randint(10000000, 99999999)}",
            "arn": random.choice(SAMPLE_ARNS),
            "accountId": "123456789012",
        },
        "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": EVENT_SOURCES.get(event_name, "aws.amazonaws.com"),
        "eventName": event_name,
        "awsRegion": random.choice(REGIONS),
        "sourceIPAddress": random.choice(SAMPLE_IPS),
        "userAgent": "aws-cli/2.15.0 Python/3.11.6",
        "requestParameters": {},
        "responseElements": {},
    }

    # Simulate occasional failures
    if random.random() > 0.8:
        event["errorCode"] = random.choice(["AccessDenied", "UnauthorizedAccess", "ValidationException"])
        event["errorMessage"] = "User is not authorized to perform this operation"

    return event


def push_to_loki(loki_url: str, events: list[dict]):
    streams = [{
        "stream": {
            "job": "cloudtrail",
            "source": "sandbox-injector",
            "aws_account": "123456789012",
        },
        "values": []
    }]

    for event in events:
        ts = str(int(time.time() * 1e9))
        streams[0]["values"].append([ts, json.dumps(event)])
        time.sleep(0.001)

    payload = json.dumps({"streams": streams}).encode()
    req = Request(
        f"{loki_url}/loki/api/v1/push",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=10) as resp:
            if resp.status < 300:
                print(f"  Pushed {len(events)} events to Loki")
            else:
                print(f"  Loki returned {resp.status}")
    except Exception as e:
        print(f"  Failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Inject CloudTrail events into Loki")
    parser.add_argument("--loki-url", default="http://localhost:3100")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--events", type=str, default="", help="Comma-separated event names")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    event_names = [e.strip() for e in args.events.split(",") if e.strip()] or None

    events = []
    for _ in range(args.count):
        name = random.choice(event_names) if event_names else None
        events.append(generate_event(name))

    event_counts = {}
    for e in events:
        n = e["eventName"]
        event_counts[n] = event_counts.get(n, 0) + 1

    print(f"Generated {len(events)} events:")
    for name, count in sorted(event_counts.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count}")
    print()

    if args.dry_run:
        for e in events[:3]:
            print(json.dumps(e, indent=2))
        print(f"... and {len(events) - 3} more")
        return

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
        push_to_loki(args.loki_url, batch)
        time.sleep(0.5)

    print(f"\nDone. Query: curl '{args.loki_url}/loki/api/v1/query?query={{job=\"cloudtrail\"}}&limit=5'")


if __name__ == "__main__":
    main()
