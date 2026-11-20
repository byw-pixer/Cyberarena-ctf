FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Непривилегированный пользователь и каталог под SQLite.
# Именованный volume при первом создании наследует владельца этого каталога.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data /lab-flags && chown app:app /data /lab-flags

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER app
EXPOSE 8000

# init_db.py готовит секреты, таблицы, задания и файлы заданий, затем запускает uvicorn (через exec).
CMD ["python", "init_db.py"]
