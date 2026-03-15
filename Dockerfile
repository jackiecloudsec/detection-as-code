FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY detections/ detections/
COPY engine/ engine/

ENV PYTHONPATH=/app
ENV LOKI_URL=http://loki:3100
ENV POLL_INTERVAL=60
ENV LOG_LEVEL=INFO

CMD ["python", "-m", "engine.detection_engine"]
