
FROM node:22-bookworm-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    SIMULATION_MODE=true

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHON_PATH=/opt/venv/bin/python

COPY package*.json ./
RUN npm ci --include=dev

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data/sandbox \
    /app/quarantine \
    /app/logs \
    /app/reports \
    && npm run build

ENV NODE_ENV=production

EXPOSE 10000

CMD ["npm", "start"]
