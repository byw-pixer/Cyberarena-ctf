"""Инициализация платформы при старте контейнера (CMD в app/Dockerfile).

Запускается ПЕРЕД веб-сервером и ничего не требует от оператора: достаточно `docker compose up -d --build`.

  1. SECRET_KEY: берётся из окружения, иначе создаётся случайный и сохраняется в томе /data
     (поэтому сессии и хеши флагов переживают перезапуск). В репозитории ключа нет.
  2. Администратор: ADMIN_USERNAME (по умолчанию teacher). Если ADMIN_PASSWORD не задан и
     администратора ещё нет, создаётся случайный пароль и один раз выводится в лог контейнера.
     Саму учётную запись создаёт main.py при старте (с обязательной сменой пароля при первом входе).
  3. Таблицы SQLite создаются, если их нет. Если таблица заданий пуста, добавляются WEB-01, WEB-02,
     CRYPTO-01. Дальше при каждом старте флаги этих трёх заданий синхронизируются с переменными
     WEB01_FLAG, WEB02_FLAG, CRYPTO01_FLAG (демонстрационные значения, если переменные не заданы),
     так что смена флага в .env не рассинхронизирует базу и лабораторию.
  4. Файлы заданий WEB-02 и CRYPTO-01 создаются из флагов (раздаются по адресу /static/).
  5. Флаги убираются из окружения процесса, и через exec запускается uvicorn.

Флаги и пароли в лог не попадают, кроме одноразового пароля администратора из пункта 2.
"""
import os
import secrets
import sqlite3
import sys
from pathlib import Path

import task_files as tf

APP_DIR = Path(__file__).resolve().parent
DEFAULT_DATABASE_URL = "sqlite:////data/cyberarena.db"
MIN_SECRET_LEN = 32
MIN_PASSWORD_LEN = 12


def sqlite_path(database_url):
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise tf.ConfigError("поддерживается только SQLite: DATABASE_URL должен начинаться с sqlite:///")
    return database_url[len(prefix):]


def resolve_secret_key(environ, data_dir):
    """Возвращает (ключ, источник). Источник: env | file | generated."""
    value = (environ.get("SECRET_KEY") or "").strip()
    if value:
        if len(value) < MIN_SECRET_LEN:
            raise tf.ConfigError("SECRET_KEY слишком короткий: нужно не меньше %d символов (или удалите его из .env)" % MIN_SECRET_LEN)
        return value, "env"
    path = Path(data_dir) / "secret_key"
    if path.is_file():
        stored = path.read_text(encoding="utf-8").strip()
        if len(stored) >= MIN_SECRET_LEN:
            return stored, "file"
    generated = secrets.token_urlsafe(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(generated)
    return generated, "generated"


def user_exists(db_path, username):
    """Есть ли пользователь в базе (False, если базы или таблицы ещё нет)."""
    if not Path(db_path).is_file():
        return False
    try:
        con = sqlite3.connect(db_path, timeout=20)
        try:
            return con.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is not None
        finally:
            con.close()
    except sqlite3.Error:
        return False


def resolve_admin(environ, db_path):
    """Возвращает (логин, пароль для main.py, показать_пароль_в_логе, администратор_создаётся_сейчас)."""
    username = (environ.get("ADMIN_USERNAME") or "").strip() or "teacher"
    if len(username) > 40:
        raise tf.ConfigError("ADMIN_USERNAME длиннее 40 символов")
    is_new = not user_exists(db_path, username)
    password = environ.get("ADMIN_PASSWORD") or ""
    if password:
        if len(password) < MIN_PASSWORD_LEN:
            raise tf.ConfigError("ADMIN_PASSWORD слишком короткий: нужно не меньше %d символов (или удалите его из .env)" % MIN_PASSWORD_LEN)
        return username, password, False, is_new
    if is_new:
        return username, secrets.token_urlsafe(12), True, True     # 16 символов, показываем один раз
    return username, secrets.token_urlsafe(24), False, False       # администратор уже есть, пароль не используется


def seed_database(engine, secret, flags):
    """Создаёт таблицы и задания. Возвращает (создано, флагов обновлено)."""
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session
    from models import Base, Challenge

    Base.metadata.create_all(engine)
    created = refreshed = 0
    with Session(engine) as db:
        total = db.scalar(select(func.count()).select_from(Challenge))
        for item in tf.CHALLENGES:
            flag_hash = tf.hash_flag(secret, flags[item["flag_env"]])
            row = db.scalar(select(Challenge).where(Challenge.title.startswith(item["code"])).order_by(Challenge.id))
            if row is None:
                if total == 0:                      # заполняем только пустую базу
                    db.add(Challenge(
                        title=item["title"], category=item["category"], difficulty=item["difficulty"],
                        description=item["description"], points=item["points"], flag_hash=flag_hash,
                        is_published=True, resource_url=item["resource_url"],
                    ))
                    created += 1
            elif row.flag_hash != flag_hash:
                row.flag_hash = flag_hash           # флаг в .env изменился
                refreshed += 1
        db.commit()
    return created, refreshed


def print_banner(username, password):
    line = "=" * 64
    print(line)
    print("  CYBERARENA: создана учётная запись администратора")
    print("  Логин:  %s" % username)
    print("  Пароль: %s" % password)
    print("  Пароль показан один раз. При первом входе платформа попросит его сменить.")
    print(line, flush=True)


def main():
    environ = os.environ
    database_url = environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    data_dir = Path(environ.get("DATA_DIR") or "/data")
    static_dir = Path(environ.get("STATIC_DIR") or "/tmp/cyberarena-static")
    try:
        db_path = sqlite_path(database_url)
        secret, secret_source = resolve_secret_key(environ, data_dir)
        username, password, show_password, admin_is_new = resolve_admin(environ, db_path)
        flags = tf.load_flags(environ)
    except tf.ConfigError as err:
        print("ОШИБКА НАСТРОЙКИ: %s" % err, file=sys.stderr, flush=True)
        return 1

    from sqlalchemy import create_engine
    engine = create_engine(database_url, connect_args={"timeout": 20})
    try:
        created, refreshed = seed_database(engine, secret, flags)
    finally:
        engine.dispose()
    tf.prepare_static(APP_DIR / "static", static_dir, flags)

    print("Инициализация: SECRET_KEY из %s; заданий добавлено %d, флагов обновлено %d; файлы заданий созданы."
          % ({"env": "окружения", "file": "тома /data", "generated": "тома /data (создан при первом запуске)"}[secret_source],
             created, refreshed), flush=True)
    if show_password:
        print_banner(username, password)
    elif admin_is_new:
        print("Администратор %s будет создан с паролем из ADMIN_PASSWORD." % username, flush=True)

    # Дальше работает только веб-процесс: ему нужны настройки, но не флаги заданий.
    for name in list(tf.DEFAULT_FLAGS) + ["CRYPTO01_KEY"]:
        os.environ.pop(name, None)
    os.environ.update({
        "SECRET_KEY": secret, "ADMIN_USERNAME": username, "ADMIN_PASSWORD": password,
        "DATABASE_URL": database_url, "STATIC_DIR": str(static_dir),
    })
    os.execv(sys.executable, [
        sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000",
        "--proxy-headers", "--forwarded-allow-ips", "*",
    ])


if __name__ == "__main__":
    sys.exit(main())
