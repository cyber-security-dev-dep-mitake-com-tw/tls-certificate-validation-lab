FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/
# Services execute as a non-root user. The shared trust volume is populated by SVC1.
RUN useradd --uid 10001 --create-home lab && mkdir -p /state /trust /reports \
    && chown -R lab:lab /state /trust /reports /app
USER lab
