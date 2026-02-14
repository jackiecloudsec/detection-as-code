FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx

COPY detections/ detections/
COPY engine/ engine/

ENV PYTHONPATH=/app
ENV LOKI_URL=http://loki:3100

CMD ["python", "-m", "engine.detection_engine"]
