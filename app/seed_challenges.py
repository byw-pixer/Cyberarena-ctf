"""Загрузка учебных заданий WEB-01, WEB-02, CRYPTO-01 в базу платформы.

Запускается внутри контейнера app скриптом scripts/seed.sh. Флаги передаются через
окружение только на время запуска (WEB01_FLAG, WEB02_FLAG, CRYPTO01_FLAG), в контейнере
они не остаются. Хеш считается по той же формуле, что hash_flag() в main.py:
HMAC-SHA256 с ключом SECRET_KEY. Поэтому SECRET_KEY после загрузки менять нельзя
(иначе все флаги перестанут приниматься).

Скрипт идемпотентен: задание с тем же названием обновляется, а не дублируется, и его
признак «опубликовано» сохраняется. Флаги нигде не печатаются.
Только стандартная библиотека: ни FastAPI, ни SQLAlchemy не нужны.
"""
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

SEED_PATH = Path(__file__).parent / "seed" / "challenges.json"
FLAG_RE = re.compile(r"^CTF\{[^{}\r\n]{1,160}\}$")      # тот же формат, что принимает платформа
COLUMNS = ("title", "category", "difficulty", "description", "points",
           "flag_hash", "is_published", "resource_url")


def hash_flag(secret, flag):
    """Формула платформы (main.py): HMAC-SHA256(SECRET_KEY, флаг)."""
    return hmac.new(secret.encode(), flag.encode(), hashlib.sha256).hexdigest()


def sqlite_path(database_url):
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("загрузчик поддерживает только SQLite (DATABASE_URL=sqlite:///...)")
    return database_url[len(prefix):]


def load_challenges(conn, items, flags, secret):
    """Создаёт или обновляет задания. Возвращает (создано, обновлено)."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(challenges)")}
    if not columns:
        raise RuntimeError("таблицы challenges ещё нет: сначала запустите платформу (docker compose up -d)")
    missing = set(COLUMNS) - columns
    if missing:
        raise RuntimeError("в таблице challenges нет столбцов: %s" % ", ".join(sorted(missing)))
    created = updated = 0
    for item in items:
        flag = flags.get(item["flag_env"], "")
        if not FLAG_RE.match(flag):
            raise ValueError("%s не задан или не в формате CTF{...}" % item["flag_env"])
        flag_hash = hash_flag(secret, flag)
        row = conn.execute("SELECT id FROM challenges WHERE title = ?", (item["title"],)).fetchone()
        if row:
            conn.execute(
                "UPDATE challenges SET category=?, difficulty=?, description=?, points=?, "
                "flag_hash=?, resource_url=? WHERE id=?",
                (item["category"], item["difficulty"], item["description"], item["points"],
                 flag_hash, item["resource_url"], row[0]),
            )
            updated += 1
        else:
            conn.execute(
                "INSERT INTO challenges (title, category, difficulty, description, points, "
                "flag_hash, is_published, resource_url) VALUES (?,?,?,?,?,?,?,?)",
                (item["title"], item["category"], item["difficulty"], item["description"],
                 item["points"], flag_hash, 1 if item["is_published"] else 0, item["resource_url"]),
            )
            created += 1
    conn.commit()
    return created, updated


def main():
    secret = os.environ.get("SECRET_KEY", "")
    if len(secret) < 32:
        print("Ошибка: SECRET_KEY не задан или короче 32 символов", file=sys.stderr)
        return 1
    database_url = os.environ.get("DATABASE_URL", "sqlite:///./cyberarena.db")
    items = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    flags = {name: os.environ.get(name, "") for name in {i["flag_env"] for i in items}}
    try:
        conn = sqlite3.connect(sqlite_path(database_url), timeout=20)
        try:
            created, updated = load_challenges(conn, items, flags, secret)
        finally:
            conn.close()
    except (ValueError, RuntimeError, sqlite3.Error) as err:
        print("Ошибка:", err, file=sys.stderr)
        return 1
    print("Задания загружены: создано %d, обновлено %d." % (created, updated))
    return 0


if __name__ == "__main__":
    sys.exit(main())
