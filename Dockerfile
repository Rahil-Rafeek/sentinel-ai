# Multi-stage Dockerfile for Sentinel AI (Production Cloud Hosting)
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and application code
COPY backend ./backend
COPY data ./data
COPY models ./models

# Copy compiled frontend from builder
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

EXPOSE 8000

# Start server using dynamic PORT assigned by cloud provider (Render, Railway, Hugging Face)
CMD sh -c "python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"

