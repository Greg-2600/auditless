FROM python:3.14-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY linux_health/ /app/linux_health/

# Create reports directory and non-root runtime user
RUN mkdir -p /app/reports \
    && useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

# Dashboard port (local web UI via --serve)
EXPOSE 8080

# Set the entry point
ENTRYPOINT ["python", "-m", "linux_health"]
CMD ["--help"]

# Verify CLI loads correctly
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -m linux_health --help || exit 1
