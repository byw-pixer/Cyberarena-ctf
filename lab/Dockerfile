FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN adduser -D -u 10001 lab
WORKDIR /srv
COPY app.py .

USER lab
EXPOSE 5000
CMD ["python", "app.py"]
