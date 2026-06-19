FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app/cryptosite

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app/cryptosite
RUN mkdir -p /app/data/uploads/kyc

WORKDIR /app/cryptosite/backend
EXPOSE 8000

CMD ["sh", "-c", "python -c "from app import init_db; init_db()" && exec gunicorn -c gunicorn.conf.py app:app"]
