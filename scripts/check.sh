#!/usr/bin/env bash
# Проверки приёмки для инфраструктуры. Запускать при поднятом стеке:
#   docker compose up -d --build && ./scripts/check.sh
cd "$(dirname "$0")/.."

FAILED=0
ok()   { echo "[ OK ] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }

LAB_ID=$(docker compose ps -q lab-web)
APP_ID=$(docker compose ps -q app)
lab_inspect() { docker inspect "$LAB_ID" --format "$1"; }

# доступность
curl -fsSL -o /dev/null http://localhost:8080/    && ok "платформа открывается на localhost:8080" || fail "платформа не открывается на :8080"
curl -fsSL -o /dev/null http://localhost:8080/lab/ && ok "лаборатория открывается через /lab/"    || fail "лаборатория не открывается через /lab/"
[[ "$(docker compose port nginx 80)" == "127.0.0.1:8080" ]] && ok "nginx слушает только 127.0.0.1:8080" || fail "nginx опубликован не только на 127.0.0.1"
[[ "$(docker inspect "$APP_ID" --format '{{json .HostConfig.PortBindings}}')" == "{}" ]] && ok "платформа не опубликована наружу напрямую" || fail "порт платформы опубликован наружу"

# изоляция лаборатории
if docker compose exec -T lab-web python -c "import socket; socket.create_connection(('app', 8000), 2)" >/dev/null 2>&1; then
  fail "лаборатория МОЖЕТ достучаться до платформы"; else ok "лаборатория не видит платформу"; fi
if docker compose exec -T lab-web python -c "import socket; socket.create_connection(('1.1.1.1', 53), 2)" >/dev/null 2>&1; then
  fail "у лаборатории есть выход в интернет"; else ok "у лаборатории нет выхода в интернет"; fi
lab_inspect '{{json .Mounts}}' | grep -q docker.sock && fail "в лабораторию смонтирован docker.sock" || ok "docker.sock в лабораторию не смонтирован"
[[ "$(lab_inspect '{{.HostConfig.Privileged}}')" == "false" ]] && ok "лаборатория не privileged" || fail "лаборатория privileged"
[[ "$(lab_inspect '{{.HostConfig.ReadonlyRootfs}}')" == "true" ]] && ok "корневая ФС лаборатории read-only" || fail "корневая ФС лаборатории доступна на запись"
[[ "$(lab_inspect '{{.HostConfig.NetworkMode}}')" != "host" ]] && ok "лаборатория без host network" || fail "лаборатория в host network"
[[ "$(docker compose exec -T lab-web id -u | tr -d '\r')" != "0" ]] && ok "лаборатория работает не от root" || fail "лаборатория работает от root"

# конфигурация и секреты
if docker compose exec -T nginx nginx -t >/dev/null 2>&1; then ok "конфигурация Nginx корректна (nginx -t)"; else fail "nginx -t сообщает об ошибке конфигурации"; fi
if [[ -f .env ]]; then
  secret=$(grep -E '^SECRET_KEY=' .env | tail -n1 | cut -d= -f2- || true)
  admin_pw=$(grep -E '^ADMIN_PASSWORD=' .env | tail -n1 | cut -d= -f2- || true)
  [[ ${#secret} -ge 32 && "$secret" != *CHANGE_ME* ]] && ok "SECRET_KEY задан (32+ символов, не заглушка)" || fail "SECRET_KEY короткий или остался заглушкой"
  [[ ${#admin_pw} -ge 12 && "$admin_pw" != *CHANGE_ME* ]] && ok "ADMIN_PASSWORD задан (12+ символов, не заглушка)" || fail "ADMIN_PASSWORD короткий или остался заглушкой"
else
  fail ".env не найден (создайте: ./scripts/init-env.sh)"
fi
curl -fsS -o /dev/null http://localhost:8080/static/style.css && ok "Nginx раздаёт /static/ (стили)" || fail "/static/style.css недоступен"

# задания и флаги
if docker compose exec -T app env | grep -q 'CTF{'; then
  fail "флаги заданий попали в окружение платформы"; else ok "флаги заданий не попали в окружение платформы"; fi
if curl -fsSL http://localhost:8080/ | grep -q 'CTF{'; then
  fail "флаг виден на главной странице платформы"; else ok "на главной странице платформы флагов нет"; fi
curl -fsS "http://localhost:8080/lab/notes?id=3" | grep -q 'CTF{' && fail "своя заметка (id=3) не должна содержать флаг" || ok "WEB-01: своя заметка флага не содержит"
curl -fsS "http://localhost:8080/lab/notes?id=1" | grep -q 'CTF{' && ok "WEB-01 решается через Nginx (notes?id=1)" || fail "WEB-01: флаг не получен через notes?id=1"
curl -fsS -o /dev/null http://localhost:8080/static/tasks/web02/vault.js && ok "WEB-02: файлы задания доступны" || fail "WEB-02: vault.js недоступен (платформа не отдаёт /static/)"
curl -fsS -o /dev/null http://localhost:8080/static/tasks/crypto01/cipher.txt && ok "CRYPTO-01: шифротекст доступен" || fail "CRYPTO-01: cipher.txt недоступен"

# отказоустойчивость: лаборатория остановлена, платформа жива
docker compose stop lab-web >/dev/null
code_lab=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/lab/)
code_root=$(curl -s -L -o /dev/null -w '%{http_code}' http://localhost:8080/)
docker compose start lab-web >/dev/null
if [[ "$code_lab" == "503" && "$code_root" == "200" ]]; then
  ok "при остановленной лаборатории: /lab/ -> 503 с понятной страницей, платформа -> 200"
else
  fail "остановленная лаборатория ломает платформу (lab=$code_lab, /=$code_root)"
fi

# ограничение частоты запросов в Nginx (в конце: после серии POST вход блокируется на ~40 секунд)
limited=0
for i in $(seq 1 45); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'x=1' http://localhost:8080/login)
  [[ "$code" == "429" ]] && limited=$((limited + 1))
done
if [[ $limited -gt 0 ]]; then ok "Nginx ограничивает частоту POST /login (429: $limited из 45)"; else fail "ограничение частоты не сработало"; fi
echo "(после проверки подождите около 40 секунд, прежде чем входить на сайт)"

echo; echo "Потребление ресурсов:"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

exit $FAILED
