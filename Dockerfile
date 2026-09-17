FROM python:3.12-slim

# Deliberately vulnerable MCP test target — LAB USE ONLY.
LABEL org.opencontainers.image.title="mcp-server-scan" \
      org.opencontainers.image.description="Deliberately vulnerable MCP server for scanner validation (e.g. Qualys TotalAI)" \
      security.warning="intentionally-vulnerable-do-not-deploy-publicly"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# Bind to all interfaces inside the container. Honor $PORT (Render/Fly/most PaaS
# inject it); default 8000 for local docker / compose.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
