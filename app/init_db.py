"""Подготовка базы, закрытой конфигурации флагов и материалов перед запуском Uvicorn."""
import json
import os
import secrets
import sqlite3
import sys
import tempfile
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
    """Возвращает (логин, пароль для main.py, сохранить_начальный_пароль, администратор_создаётся_сейчас)."""
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
        return username, secrets.token_urlsafe(12), True, True     # 16 символов, сохраняем в закрытом файле
    return username, secrets.token_urlsafe(24), False, False       # администратор уже есть, пароль не используется


def write_private(path, value):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def resolve_flags(environ, data_dir):
    path = data_dir / "task_flags.json"
    stored = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    requested = (environ.get("FLAG_REVISION") or "").strip()
    if len(requested) > 80:
        raise tf.ConfigError("FLAG_REVISION длиннее 80 символов")
    if stored and (not requested or requested == stored["revision"]):
        supplied = tf.load_flags(environ, stored["flags"])
        if supplied != stored["flags"]:
            raise tf.ConfigError("Изменение флагов требует нового FLAG_REVISION")
        return stored["flags"], stored["revision"]
    pending_path = data_dir / "task_flags.pending"
    pending = json.loads(pending_path.read_text(encoding="utf-8")) if pending_path.exists() else None
    if pending and pending["revision"] == requested:
        supplied = tf.load_flags(environ, pending["flags"])
        if supplied != pending["flags"]:
            raise tf.ConfigError("Незавершённая ротация: используйте те же значения или новую ревизию")
        return pending["flags"], requested
    # При новой ревизии пустые значения заменяются случайными флагами.
    flags = tf.load_flags(environ)
    write_private(pending_path, json.dumps({"revision": requested, "flags": flags}))
    return flags, requested


def seed_database(engine, secret, flags, revision=""):
    """Поддерживает стабильные коды заданий и только явно подтверждённую ротацию."""
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session
    from models import Base, BuiltinChallenge, Challenge

    Base.metadata.create_all(engine)
    created = refreshed = 0
    with Session(engine) as db, db.begin():
        total = db.scalar(select(func.count()).select_from(Challenge))
        for item in tf.CHALLENGES:
            code = item["code"]
            flag_hash = tf.hash_flag(secret, flags[item["flag_env"]])
            binding = db.get(BuiltinChallenge, code)
            if binding:
                row = db.get(Challenge, binding.challenge_id)
            else:
                matches = db.scalars(select(Challenge).where(
                    (Challenge.title == code) | Challenge.title.startswith(code + " ")
                    | (Challenge.resource_url == item["resource_url"])
                )).all()
                if len(matches) > 1:
                    raise tf.ConfigError(f"{code}: несколько совпадений в старой базе, требуется проверить карточки")
                row = matches[0] if matches else None
            if row is None:
                if total:
                    continue
                row = Challenge(
                    title=item["title"], category=item["category"], difficulty=item["difficulty"],
                    description=item["description"], points=item["points"], flag_hash=flag_hash,
                    is_published=True, resource_url=item["resource_url"],
                )
                db.add(row)
                db.flush()
                created += 1
            if binding and row.flag_hash != binding.configured_hash:
                raise tf.ConfigError(f"{code}: сохранённый хеш изменён вне процедуры ротации")
            if row.flag_hash != flag_hash:
                if not revision or (binding and binding.revision == revision):
                    raise tf.ConfigError(f"{code}: для смены или миграции флага требуется новый FLAG_REVISION")
                row.flag_hash = flag_hash
                refreshed += 1
            if not binding:
                binding = BuiltinChallenge(code=code, challenge_id=row.id)
                db.add(binding)
            binding.revision = revision
            binding.configured_hash = flag_hash
    return created, refreshed


def main():
    environ = os.environ
    database_url = environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL
    data_dir = Path(environ.get("DATA_DIR") or "/data")
    static_dir = Path(environ.get("STATIC_DIR") or "/tmp/cyberarena-static")
    try:
        db_path = sqlite_path(database_url)
        secret, secret_source = resolve_secret_key(environ, data_dir)
        username, password, store_password, admin_is_new = resolve_admin(environ, db_path)
        flags, revision = resolve_flags(environ, data_dir)
    except tf.ConfigError as err:
        print("ОШИБКА НАСТРОЙКИ: %s" % err, file=sys.stderr, flush=True)
        return 1

    from sqlalchemy import create_engine
    engine = create_engine(database_url, connect_args={"timeout": 20})
    try:
        created, refreshed = seed_database(engine, secret, flags, revision)
        write_private(data_dir / "task_flags.json", json.dumps({"revision": revision, "flags": flags}))
        lab_dir = Path(environ.get("LAB_FLAG_DIR") or data_dir)
        write_private(lab_dir / "web01.flag", flags["WEB01_FLAG"])
        (data_dir / "task_flags.pending").unlink(missing_ok=True)
    except tf.ConfigError as err:
        print(f"ОШИБКА НАСТРОЙКИ: {err}", file=sys.stderr, flush=True)
        return 1
    finally:
        engine.dispose()
    tf.prepare_static(APP_DIR / "static", static_dir, flags)

    print("Инициализация: SECRET_KEY из %s; заданий добавлено %d, флагов обновлено %d; файлы заданий созданы."
          % ({"env": "окружения", "file": "тома /data", "generated": "тома /data (создан при первом запуске)"}[secret_source],
             created, refreshed), flush=True)
    bootstrap = data_dir / "admin-bootstrap"
    if store_password:
        write_private(bootstrap, password + "\n")
        print("Создаётся администратор %s. Начальный пароль сохранён в закрытом файле /data/admin-bootstrap."
              % username, flush=True)
    elif admin_is_new:
        print("Администратор %s будет создан с паролем из ADMIN_PASSWORD." % username, flush=True)

    # Дальше работает только веб-процесс: ему нужны настройки, но не флаги заданий.
    for name in (*tf.FLAG_NAMES, "FLAG_REVISION"):
        os.environ.pop(name, None)
    os.environ.update({
        "SECRET_KEY": secret, "ADMIN_USERNAME": username, "ADMIN_PASSWORD": password,
        "DATABASE_URL": database_url, "STATIC_DIR": str(static_dir), "ADMIN_BOOTSTRAP_FILE": str(bootstrap),
    })
    os.execv(sys.executable, [
        sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000",
        "--proxy-headers", "--forwarded-allow-ips", "*",
    ])


if __name__ == "__main__":
    sys.exit(main())
