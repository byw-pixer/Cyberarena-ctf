#!/usr/bin/env bash
# Создаёт .env со случайными секретами. Существующий .env не перезаписывает.
# Флаги заданий берутся из .env.example (демонстрационные): перед реальным турниром смените их.
# Работает в Linux, macOS, WSL и Git Bash (Windows): ищет python3, затем python, затем openssl.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] && { echo ".env уже существует, ничего не меняю"; exit 0; }

PY=""
for candidate in python3 python; do
  if "$candidate" -c "import secrets" >/dev/null 2>&1; then PY=$candidate; break; fi
done

rand() {   # rand N: случайная строка не короче N символов
  if [[ -n "$PY" ]]; then
    "$PY" -c "import secrets; print(secrets.token_urlsafe($1))"
  else
    openssl rand -base64 48 | tr -d '=+/\r\n' | cut -c1-"$(( $1 * 4 / 3 ))"
  fi
}

admin_password=$(rand 14)

{
  echo "SECRET_KEY=$(rand 48)"
  echo "ADMIN_USERNAME=teacher"
  echo "ADMIN_PASSWORD=${admin_password}"
  echo
  grep -E '^(WEB01_FLAG|WEB02_FLAG|CRYPTO01_FLAG)=' .env.example | tr -d '\r'
} > .env
chmod 600 .env 2>/dev/null || true

echo ".env создан."
echo "Логин администратора: teacher"
echo "Пароль администратора: ${admin_password}"
echo "(при первом входе платформа попросит сменить пароль)"
