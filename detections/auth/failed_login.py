"""Multiple failed logins from same IP - example detection for testing."""

def logql_query():
    return '{job="auth-logs"} |= "failed login"'

def detect(event):
    return event.get("failed_count", 0) >= 3

def title(event):
    return f"Failed logins from {event.get('source_ip', 'unknown')}"

def severity(event):
    return "MEDIUM"

def runbook(event):
    return "https://github.com/yourrepo/runbooks/failed_login.md"

failed_login = type("Detection", (), {
    "logql_query": staticmethod(logql_query),
    "detect": staticmethod(detect),
    "title": staticmethod(title),
    "severity": staticmethod(severity),
    "runbook": staticmethod(runbook),
    "name": "failed_login",
})()
