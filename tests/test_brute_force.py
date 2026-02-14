import pytest
from detections.auth.brute_force import brute_force


def test_brute_force_logql():
    assert "auth-logs" in brute_force.logql_query()
    assert "authentication failure" in brute_force.logql_query()


def test_brute_force_detect_below_threshold():
    assert brute_force.detect({"failure_count": 3}) is False
    assert brute_force.detect({"failure_count": 4}) is False


def test_brute_force_detect_at_or_above_threshold():
    assert brute_force.detect({"failure_count": 5}) is True
    assert brute_force.detect({"failure_count": 10}) is True


def test_brute_force_title():
    assert "10.0.0.1" in brute_force.title({"source_ip": "10.0.0.1"})
    assert "unknown" in brute_force.title({})


def test_brute_force_severity():
    assert brute_force.severity({}) == "HIGH"
