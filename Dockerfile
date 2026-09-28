FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY sitemonitor/ sitemonitor/
COPY monitor.py .

# Run unprivileged. data/ and logs/ are volumes (see docker-compose.yml).
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin monitor \
    && mkdir -p /app/data /app/logs \
    && chown -R monitor:monitor /app
USER monitor

EXPOSE 8080

# Fails when no check cycle completed recently (scheduler stuck) or the dashboard is down.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).status == 200 else 1)"

CMD ["python", "monitor.py", "--config", "/app/config.yaml", "run"]
