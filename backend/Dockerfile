# SafeInbox AI - Cloud Backend Dockerfile
# Optimized for Google Cloud Run

FROM python:3.12-slim

WORKDIR /app

# Install compilation tools for binary extensions (asyncpg / greenlet)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies directly into the system environment
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and migration code
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

EXPOSE 8080/tcp

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 2 --timeout-keep-alive 30"]

