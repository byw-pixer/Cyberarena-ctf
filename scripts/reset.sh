#!/usr/bin/env bash
# Полный сброс: пользователи, попытки, решения, рейтинг и задания (задания загружаются заново).
set -euo pipefail
cd "$(dirname "$0")/.."

read -r -p "Удалить ВСЕ данные платформы? [y/N] " answer
[[ "$answer" == "y" ]] || { echo "Отмена"; exit 1; }

docker compose down -v          # -v удаляет volume с SQLite
docker compose up -d --build
echo "База пересоздана, администратор создан из .env. Загружаю задания..."
./scripts/seed.sh || echo "Задания не загружены: выполните ./scripts/seed.sh вручную"
echo "Готово."
