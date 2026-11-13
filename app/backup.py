"""Резервная копия SQLite (консистентная, пока платформа работает).

    docker compose exec app python backup.py
    docker compose cp app:/data/backup.db ./backup.db

Файл /data/backup.db перезаписывается при каждом запуске.
"""
import os
import sqlite3
import sys
from pathlib import Path


def main():
    url = os.environ.get("DATABASE_URL") or "sqlite:////data/cyberarena.db"
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        print("Поддерживается только SQLite", file=sys.stderr)
        return 1
    source_path = Path(url[len(prefix):])
    target_path = source_path.with_name("backup.db")
    if not source_path.is_file():
        print("База данных не найдена: %s" % source_path, file=sys.stderr)
        return 1
    source = sqlite3.connect(source_path, timeout=20)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)        # штатный механизм SQLite: корректен и при работающей платформе
    finally:
        target.close()
        source.close()
    print("Резервная копия: %s" % target_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
