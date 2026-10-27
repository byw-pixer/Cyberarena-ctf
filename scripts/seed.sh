#!/usr/bin/env bash
# Загружает три учебных задания в базу платформы. Флаги берутся из .env и передаются
# в контейнер только на время запуска. Платформа должна быть запущена.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "Нет файла .env (создайте его: ./scripts/init-env.sh)"; exit 1; }

for name in WEB01_FLAG WEB02_FLAG CRYPTO01_FLAG; do
  value=$(grep -E "^${name}=" .env | tail -n1 | cut -d= -f2- | tr -d "\r" || true)
  value=${value%\"}; value=${value#\"}
  [[ -n "$value" ]] || { echo "В .env не задан $name"; exit 1; }
  export "$name=$value"
done

docker compose exec -T -e WEB01_FLAG -e WEB02_FLAG -e CRYPTO01_FLAG app python seed_challenges.py
