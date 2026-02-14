"""Brute force authentication failure detection."""

def logql_query():
    return '{job="auth-logs"} |= "authentication failure"'

def detect(event):
    return event.get("failure_count", 0) >= 5

def title(event):
    return f"Brute force from {event.get('source_ip', 'unknown')}"

def severity(event):
    return "HIGH"

def runbook(event):
    return "https://github.com/yourrepo/runbooks/brute_force.md"

# Export as object for engine
brute_force = type("Detection", (), {
    "logql_query": staticmethod(logql_query),
    "detect": staticmethod(detect),
    "title": staticmethod(title),
    "severity": staticmethod(severity),
    "runbook": staticmethod(runbook),
    "name": "brute_force",
})()
