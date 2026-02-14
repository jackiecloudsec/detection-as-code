import pytest
from engine.log_parser import parse_log_line


def test_parse_json():
    line = '{"source_ip": "1.2.3.4", "failure_count": 5}'
    assert parse_log_line(line) == {"source_ip": "1.2.3.4", "failure_count": 5}


def test_parse_key_value():
    line = "source_ip=10.0.0.1 failure_count=3"
    out = parse_log_line(line)
    assert out.get("source_ip") == "10.0.0.1"
    assert out.get("failure_count") == "3"


def test_parse_empty():
    assert parse_log_line("") == {}
    assert parse_log_line("   ") == {}
