# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /w
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH" \
    SENTINEL_DATABASE_PATH=/data/sentinel.db
RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown sentinel:sentinel /data
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=sentinel:sentinel backend ./backend
COPY --chown=sentinel:sentinel frontend ./frontend
USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=3).status == 200 else 1)"
# --factory: the app is built by create_app(); nothing runs at import time.
# Single worker on purpose: SQLite + in-process rate limiter. Scale out only after moving to a shared store.
CMD ["uvicorn", "backend.app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
