# Задания CyberArena

| ID | Баллы | Категория | Где живёт | Файлы |
|---|---|---|---|---|
| WEB-01 | 100 | Web | контейнер `lab-web`, `/lab/` | `lab/app.py` |
| WEB-02 | 150 | Web | статика платформы | `app/static/tasks/web02/` |
| CRYPTO-01 | 150 | Crypto | статика платформы | `app/static/tasks/crypto01/cipher.txt` |

Флаги задаются в `.env` (`WEB01_FLAG`, `WEB02_FLAG`, `CRYPTO01_FLAG`). После смены флагов:

```bash
python3 tasks/build_tasks.py     # пересоздаёт vault.js, cipher.txt и app/seed/challenges.json
docker compose up -d --build
./scripts/seed.sh                # обновляет задания и хеши флагов в базе платформы
```

`app/seed/challenges.json` содержит карточки заданий (название, категория, сложность, описание, баллы, `resource_url`) без флагов и без хешей.
Хеши считает `app/seed_challenges.py` по формуле платформы: HMAC-SHA256 с `SECRET_KEY`. Загрузка: `./scripts/seed.sh`.
Файлы `/static/` раздаёт Nginx из `app/static/`.

Тесты: `python3 -m unittest discover -s tests -p "test_[ti]*.py" -v` или `pytest -q`. Чек-лист приёмки: `tests/ACCEPTANCE_CHECKLIST.md`.
Write-up преподавателя: `teacher/writeups/`.
