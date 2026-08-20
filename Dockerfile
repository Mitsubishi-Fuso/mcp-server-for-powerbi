# Multi-stage build for MCP Server for Power BI (HTTP Mode)
# Optimized for production deployment with Alpine Linux

# Stage 1: Build stage with uv and Alpine
FROM ghcr.io/astral-sh/uv:python3.12-alpine AS builder

# Set working directory
WORKDIR /app

# Copy dependency files and source code
COPY pyproject.toml uv.lock ./
COPY mcp_for_powerbi ./mcp_for_powerbi

# Install into a venv the runtime stage can copy wholesale. --no-editable so the
# package is installed properly rather than linked back to the build context.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN uv sync --locked --no-dev --no-editable --no-cache

# Stage 2: Runtime stage - minimal Alpine production image
FROM python:3.12-alpine

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    MCP_HOST=0.0.0.0 \
    PORT=8080

# Create non-root user for security
RUN adduser -D -u 1000 mcpuser && \
    mkdir -p /app && \
    chown -R mcpuser:mcpuser /app

# Copy virtual environment from builder (already contains installed package)
COPY --from=builder --chown=mcpuser:mcpuser /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Switch to non-root user
USER mcpuser

# Health check for Azure Container Apps. Addressed by literal IPv4: uvicorn
# binds 0.0.0.0, while `localhost` resolves to ::1 first inside the image, so
# the probe was refused and the container never reported healthy.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider "http://127.0.0.1:${PORT}/" || exit 1

# Expose HTTP port
EXPOSE 8080

# Run the MCP server with HTTP transport
CMD ["mcp-for-powerbi-http"]
