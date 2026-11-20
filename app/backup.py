"""Create and check a private SQLite snapshot while the application is running."""
import argparse
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Новый путь к файлу резервной копии")
    args = parser.parse_args()
    url = os.environ.get("DATABASE_URL") or "sqlite:////data/cyberarena.db"
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        parser.error("Поддерживается только SQLite")
    source_path = Path(url[len(prefix):]).resolve(strict=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target_path = (args.output or source_path.with_name(f"backup-{stamp}.db")).resolve()
    fd, name = tempfile.mkstemp(dir=target_path.parent, prefix=".sqlite-backup-")
    os.close(fd)
    temporary = Path(name)
    try:
        with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=20)) as source:
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise RuntimeError("Проверка целостности резервной копии не прошла")
            finally:
                target.close()
        os.link(temporary, target_path)
    finally:
        temporary.unlink(missing_ok=True)
    print(target_path)


if __name__ == "__main__":
    main()
