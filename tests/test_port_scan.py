import pytest
from detections.network.port_scan import port_scan


def test_port_scan_logql():
    assert "network-logs" in port_scan.logql_query()


def test_port_scan_detect():
    assert port_scan.detect({"unique_ports": 5}) is False
    assert port_scan.detect({"unique_ports": 10}) is True
    assert port_scan.detect({"unique_ports": 20}) is True
    assert port_scan.detect({}) is False
