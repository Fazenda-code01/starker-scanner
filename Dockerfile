# =========================================================
# STARKER Security Scanner v5.0 — Docker Image
# =========================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="STARKER Consulting"
LABEL version="5.0"
LABEL description="Enterprise defensive security scanner"

# Working directory
WORKDIR /app

# Copy files
COPY requirements.txt .
COPY scanner.py .

# Install dependencies (no cache = smaller image)
RUN pip install --no-cache-dir -r requirements.txt

# Non-root user for security
RUN useradd -m -u 1000 scanner
USER scanner

# Output directory (mount here to retrieve reports)
VOLUME ["/app/reports"]

# Entrypoint
ENTRYPOINT ["python", "scanner.py"]

# Default command (override with your target)
CMD ["--help"]
