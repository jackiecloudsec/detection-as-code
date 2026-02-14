# Detection rules

Add new detection modules here. Each detection should provide:

- **`logql_query()`** — LogQL string to pull relevant logs from Loki
- **`detect(event)`** — Returns `True` if the event should trigger an alert
- **`title(event)`** — Short alert title
- **`severity(event)`** — e.g. `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- **`runbook(event)`** — URL or text for runbook

Export a single object (e.g. `my_detection`) and register it in `engine/detection_engine.py` in the `DETECTIONS` list. Add tests under `tests/` for each new rule.
