"""Port scan detection from network logs."""

def logql_query():
    return '{job="network-logs"} |= "connection"'

def detect(event):
    return event.get("unique_ports", 0) >= 10

def title(event):
    return f"Port scan from {event.get('source_ip', 'unknown')}"

def severity(event):
    return "MEDIUM"

def runbook(event):
    return "https://github.com/yourrepo/runbooks/port_scan.md"

port_scan = type("Detection", (), {
    "logql_query": staticmethod(logql_query),
    "detect": staticmethod(detect),
    "title": staticmethod(title),
    "severity": staticmethod(severity),
    "runbook": staticmethod(runbook),
    "name": "port_scan",
})()
