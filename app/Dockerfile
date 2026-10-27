FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# непривилегированный пользователь + каталог под SQLite
# (именованный volume при первом создании наследует владельца этого каталога)
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER app
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
