FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY src/ ./src/
COPY data/ ./data/

CMD ["python", "-m", "src.logsentinel.main"]
