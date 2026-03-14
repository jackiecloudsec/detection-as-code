import pytest
from detections.auth.failed_login import failed_login


def test_failed_login_logql():
    assert "auth-logs" in failed_login.logql_query()
    assert "failed login" in failed_login.logql_query()


def test_failed_login_detect():
    assert failed_login.detect({"failed_count": 2}) is False
    assert failed_login.detect({"failed_count": 3}) is True
    assert failed_login.detect({"failed_count": 10}) is True
    assert failed_login.detect({}) is False


def test_failed_login_title():
    assert "1.2.3.4" in failed_login.title({"source_ip": "1.2.3.4"})


def test_failed_login_severity():
    assert failed_login.severity({}) == "MEDIUM"
