# CYBERARENA — backend (роль №1)

Реализованы SQLAlchemy-модели User, Challenge, Submission и Solve, авторизация с Argon2, сессии и CSRF, хранение HMAC-SHA256 флагов, регистрация, профиль, рейтинг, защита от двойного начисления, ограничение попыток, административные CRUD-формы и сброс турнира.

## Первый запуск

1. Создайте .env по .env.example и замените примерные значения на длинные уникальные секреты.
2. Выполните `docker compose up -d --build`.
3. Откройте http://localhost:8080. Администратор обязан сменить начальный пароль при первом входе.
4. Через /admin создайте и опубликуйте задания; Web-лаборатория доступна отдельно по /lab/.

## Контракт с командой

- FastAPI приложение: `app/main.py`, переменная `app`, порт 8000, GET /health.
- База SQLite: `DATABASE_URL=sqlite:////data/cyberarena.db`, отдельный docker volume.
- Jinja2: каталог /challenges, карточка /challenges/{id}, рейтинг /leaderboard, профиль /profile, админка /admin.
- Для локальных проверок: `pip install -r app/requirements.txt pytest httpx`, затем `pytest -q`.

Текущая версия базовая: отдельная проверка Docker Compose и интеграция с полноценным дизайном команды остаются задачами перед приёмкой. Не открывать лабораторию в публичный интернет.
