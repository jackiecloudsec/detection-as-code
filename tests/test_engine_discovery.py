"""Test that the detection engine discovers all modules."""
import pytest
from engine.detection_engine import discover_detections


def test_discover_finds_modules():
    detections = discover_detections()
    assert len(detections) > 0, "Should discover at least one detection module"


def test_discover_finds_categories():
    detections = discover_detections()
    categories = set()
    for det in detections:
        name = getattr(det, "__name__", "")
        parts = name.split(".")
        if len(parts) >= 2:
            categories.add(parts[1])
    # Should find at least auth and network (the original hand-written ones)
    assert "auth" in categories
    assert "network" in categories


def test_all_modules_have_required_interface():
    detections = discover_detections()
    for det in detections:
        assert hasattr(det, "logql_query"), f"{det.__name__} missing logql_query"
        assert hasattr(det, "detect"), f"{det.__name__} missing detect"
        assert callable(det.logql_query)
        assert callable(det.detect)


def test_auto_generated_modules_have_metadata():
    """Auto-generated modules from cloud-sec-blog should have metadata()."""
    detections = discover_detections()
    with_metadata = [d for d in detections if hasattr(d, "metadata")]
    # At least the auto-generated ones should have metadata
    assert len(with_metadata) > 5, f"Expected many modules with metadata(), got {len(with_metadata)}"


def test_logql_queries_are_valid_strings():
    detections = discover_detections()
    for det in detections:
        query = det.logql_query()
        assert isinstance(query, str), f"{det.__name__} logql_query returned {type(query)}"
        assert len(query) > 0, f"{det.__name__} returned empty logql_query"


def test_detect_returns_bool():
    detections = discover_detections()
    sample_event = {"eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4"}
    for det in detections:
        result = det.detect(sample_event)
        assert isinstance(result, bool), f"{det.__name__} detect() returned {type(result)}"
