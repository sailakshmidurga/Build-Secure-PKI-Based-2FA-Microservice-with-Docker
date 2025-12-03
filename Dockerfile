# ================================
# Stage 1 — Builder
# ================================
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt


# ================================
# Stage 2 — Runtime
# ================================
FROM python:3.11-slim

WORKDIR /app
ENV TZ=UTC

# Install cron + timezone support
RUN apt-get update && apt-get install -y cron tzdata && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY app/ app/
COPY scripts/ scripts/
COPY cron/2fa-cron /etc/cron.d/2fa-cron

# Copy keys
COPY student_private.pem /app/student_private.pem
COPY student_public.pem /app/student_public.pem
COPY instructor_public.pem /app/instructor_public.pem

# Cron permissions
RUN chmod 0644 /etc/cron.d/2fa-cron
RUN crontab /etc/cron.d/2fa-cron

# Create persistent storage folders
RUN mkdir /data /cron

# Expose FastAPI port
EXPOSE 8080

# Run cron + API server
CMD cron && uvicorn app.api:app --host 0.0.0.0 --port 8080
