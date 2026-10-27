#!/usr/bin/env bash
# Резервная копия SQLite (консистентная, через sqlite3 backup API).
# Восстановление: docker compose stop app
#   docker compose cp backups/<файл>.db app:/data/cyberarena.db
#   docker compose start app
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p backups
out="backups/cyberarena-$(date +%Y%m%d-%H%M%S).db"

docker compose exec -T app python -c "
import sqlite3
src = sqlite3.connect('/data/cyberarena.db')
dst = sqlite3.connect('/data/backup.tmp')
src.backup(dst)
dst.close(); src.close()
"
docker compose cp app:/data/backup.tmp "$out"
docker compose exec -T app rm -f /data/backup.tmp
echo "Готово: $out"
