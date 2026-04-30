FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

COPY connectors/otx/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY connectors/otx/connector.py /app/
COPY connectors/otx/otx_client.py /app/
COPY core /app/core
COPY exporters /app/exporters

CMD ["python", "connector.py"]
