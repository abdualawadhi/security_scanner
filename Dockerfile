FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY config/ /app/config/

RUN pip install --no-cache-dir -e .

ENV PYTHONUNBUFFERED=1
ENV WSS_DATA_DIR=/app/data

RUN mkdir -p /app/data/uploads /app/data/reports /app/data/scans

EXPOSE 5000

CMD ["wss-web", "--host", "0.0.0.0", "--port", "5000"]
