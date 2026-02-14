"""Impossible travel detection (same user, two locations in short time)."""

def logql_query():
    return '{job="auth-logs"} |= "login"'

def detect(event):
    locations = event.get("locations", [])
    if len(locations) < 2:
        return False
    return event.get("impossible_travel", False)

def title(event):
    return f"Impossible travel for user {event.get('user', 'unknown')}"

def severity(event):
    return "CRITICAL"

def runbook(event):
    return "https://github.com/yourrepo/runbooks/impossible_travel.md"

impossible_travel = type("Detection", (), {
    "logql_query": staticmethod(logql_query),
    "detect": staticmethod(detect),
    "title": staticmethod(title),
    "severity": staticmethod(severity),
    "runbook": staticmethod(runbook),
    "name": "impossible_travel",
})()
