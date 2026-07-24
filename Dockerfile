FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app

EXPOSE 8093

ENV SQLITE_PATH=/security/runtime_security.sqlite \
    AUDIT_DB_PATH=/security/audit_bus.sqlite

# Run as an unprivileged user (CIS Docker Benchmark DI-0001 / opengrep missing-user).
# Create the SQLite data dir up front and hand ownership to the non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /security \
    && chown -R appuser:appuser /security /app
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8093/health').read()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8093", "--workers", "1"]
