"""Parse log lines from Loki into event dicts."""
import json


def parse_log_line(line: str) -> dict:
    """Parse a single log line. Expects JSON; falls back to key=value or raw."""
    line = (line or "").strip()
    if not line:
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        pass
    # Simple key=value fallback
    out = {}
    for part in line.split():
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    if not out:
        out = {"raw": line}
    return out
