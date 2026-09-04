# ==========================================================
# NASWatch: Multi-Stage Production Dockerfile
# ==========================================================

FROM python:3.11-slim AS builder

WORKDIR /app

# Install system compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ==========================================================
# Runtime Stage
# ==========================================================
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime tshark and libpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap0.8 \
    wireshark-common \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r naswatch && useradd -r -g naswatch -u 10001 naswatch

# Copy virtualenv and application code
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . /app

# Set ownership
RUN mkdir -p /app/data/pcaps && \
    chown -R naswatch:naswatch /app

USER naswatch

EXPOSE 8000 8501 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: Launch FastAPI + Background Monitor or Streamlit
CMD ["uvicorn", "naswatch.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
