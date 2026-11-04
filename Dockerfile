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

# Create reports directory for mounted volumes
RUN mkdir -p /app/reports

# Set the entry point
ENTRYPOINT ["python", "-m", "linux_health"]
CMD ["--help"]

# Verify CLI loads correctly
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -m linux_health --help || exit 1
