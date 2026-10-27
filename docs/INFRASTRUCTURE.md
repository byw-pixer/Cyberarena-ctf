# CyberArena: инфраструктура и запуск

Docker Compose, Nginx, изоляция Web-лаборатории, запуск одной командой.

## Требования

- Linux (проверено на CachyOS / Arch Linux), macOS или Windows с Docker Engine и Docker Compose v2
- 8 ГБ RAM, 4 логических CPU, 10 ГБ свободного диска
- свободный порт 8080
- интернет нужен только для первой сборки образов, дальше проект работает офлайн

## Установка Docker (Arch / CachyOS)

```bash
sudo pacman -S docker docker-compose docker-buildx
sudo systemctl enable --now docker.service
sudo usermod -aG docker $USER      # затем выйти из сессии и зайти снова
docker run hello-world             # проверка
```

Пока группа `docker` не применилась, добавляйте `sudo` перед командами `docker`.

## Быстрый старт

```bash
./scripts/init-env.sh              # создаст .env со случайными секретами и покажет пароль администратора
docker compose up -d --build
./scripts/seed.sh                  # загрузит три учебных задания в базу
```

- платформа: <http://localhost:8080>
- лаборатория WEB-01: <http://localhost:8080/lab/>

Войдите как `teacher` с паролем из `init-env.sh`: платформа сразу попросит сменить пароль.
Задания после загрузки опубликованы, скрыть или изменить их можно в `/admin`.

Проверка инфраструктуры:

```bash
./scripts/check.sh
```

Проверить конфигурацию Nginx до запуска (нужен только Docker):

```bash
docker run --rm -v "$PWD/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.27-alpine nginx -t
```

## Файл `.env`

Хранит секреты, в Git не попадает. Создаётся командой `./scripts/init-env.sh` или вручную из `.env.example`.

```
SECRET_KEY=<не короче 32 символов>
ADMIN_USERNAME=teacher
ADMIN_PASSWORD=<не короче 12 символов>
WEB01_FLAG=CTF{...}
WEB02_FLAG=CTF{...}
CRYPTO01_FLAG=CTF{...}
```

Платформа не запустится, пока `SECRET_KEY` короче 32 символов, а `ADMIN_PASSWORD` короче 12.
Флаги заданий передаются только лаборатории (WEB-01) и скрипту `seed.sh` на время запуска, в окружении платформы их нет.
`SECRET_KEY` после загрузки заданий менять нельзя: от него зависят хеши флагов (HMAC), и все флаги перестанут приниматься.

Для fish (конструкция `<<'EOF'` в fish не работает) удобнее всего `./scripts/init-env.sh`: это обычный bash-скрипт.

## Задания

| ID | Баллы | Где живёт |
|---|---|---|
| WEB-01 | 100 | контейнер `lab-web`, `/lab/` |
| WEB-02 | 150 | статика `/static/tasks/web02/` |
| CRYPTO-01 | 150 | статика `/static/tasks/crypto01/` |

Статику раздаёт Nginx из папки `app/static/`. После смены флагов в `.env`:

```bash
python3 tasks/build_tasks.py       # пересоздаёт файлы WEB-02, CRYPTO-01 и список заданий
docker compose up -d --build
./scripts/seed.sh                  # обновит флаги в базе (задания обновляются, не дублируются)
```

## Ограничение частоты запросов

Nginx ограничивает `POST /login`, `POST /register` (30 в минуту, всплеск 20) и отправку флагов (120 в минуту, всплеск 60), в остальных случаях отвечает 429.
Это запасной слой против перебора скриптом: в Docker все участники приходят с одного адреса, поэтому лимиты общие и щедрые.
Основное ограничение (раз в 3 секунды на пользователя и задание) работает в самой платформе.

## Команды

| Действие | Команда |
|---|---|
| Состояние сервисов | `docker compose ps` |
| Логи | `docker compose logs -f` (или `docker compose logs -f app`) |
| Остановить / запустить | `docker compose stop` / `docker compose start` |
| Перезапуск (данные сохраняются) | `docker compose restart` |
| Пересобрать | `docker compose up -d --build` |
| Убрать контейнеры (данные остаются) | `docker compose down` |
| Полный сброс тестовых данных | `./scripts/reset.sh` |
| Резервная копия SQLite | `./scripts/backup.sh` |
| Потребление RAM и CPU | `docker stats --no-stream` |

Восстановление из резервной копии:

```bash
docker compose stop app
docker compose cp backups/<файл>.db app:/data/cyberarena.db
docker compose start app
```

## Архитектура

```
Браузер → Nginx (127.0.0.1:8080) ─┬─ /      → app (FastAPI + SQLite, volume db_data)   [app-net]
                                  └─ /lab/  → lab-web (WEB-01)                         [lab-net, internal]
```

Две Docker-сети:

- **app-net**: Nginx и платформа. Наружу выходит только порт Nginx на `127.0.0.1`.
- **lab-net** (`internal: true`): Nginx и лаборатория, без выхода в интернет.

Контейнер лаборатории не подключён к `app-net`, не видит платформу и SQLite, не получает Docker Socket.
Ограничения: non-root, read-only корневая ФС (запись только в `/tmp`), `cap_drop: ALL`, `no-new-privileges`,
0.5 CPU, 256 МБ RAM, лимит процессов. Если лаборатория остановлена, Nginx показывает страницу с кодом 503,
а платформа и рейтинг работают. База лежит в отдельном volume `db_data` и сохраняется после перезапуска.
В production для недоверенных участников нужна дополнительная изоляция на уровне VM.

## Результаты проверки (16.10.2026, CachyOS, Docker Engine + Compose v2)

`docker compose ps`: nginx, app, lab-web в статусе `healthy`, наружу опубликован только `127.0.0.1:8080->80`.

Результат `./scripts/check.sh`:

| Проверка | Результат |
|---|---|
| Платформа открывается на localhost:8080 | OK |
| Лаборатория открывается через `/lab/` | OK |
| Nginx слушает только 127.0.0.1:8080 | OK |
| Платформа не опубликована наружу напрямую | OK |
| Лаборатория не видит платформу | OK |
| У лаборатории нет выхода в интернет | OK |
| `docker.sock` в лабораторию не смонтирован | OK |
| Лаборатория не privileged | OK |
| Корневая ФС лаборатории read-only | OK |
| Лаборатория без host network | OK |
| Лаборатория работает не от root | OK |
| Лаборатория остановлена: `/lab/` → 503 с понятной страницей, платформа → 200 | OK |

Запись `lab-web could not be resolved` в логах Nginx при этой проверке ожидаема: скрипт нарочно останавливает лабораторию.

### Потребление ресурсов

| Сервис | RAM (использовано / лимит) | CPU |
|---|---|---|
| nginx | 2.2 МиБ / 64 МиБ | 0.00% |
| app | 32.4 МиБ / 512 МиБ | 0.17% |
| lab-web | 11.2 МиБ / 256 МиБ | 41.42%* |

\* замер сразу после перезапуска контейнера, кратковременный всплеск при старте.

## Решение проблем

| Симптом | Причина и решение |
|---|---|
| `env file ... .env not found` или `required variable ... is missing` | не создан `.env` или в нём нет нужных переменных: `./scripts/init-env.sh` |
| `app` не стартует, в логах `Configure SECRET_KEY (32+)...` | `SECRET_KEY` короче 32 или `ADMIN_PASSWORD` короче 12 символов |
| В каталоге нет заданий | не выполнен `./scripts/seed.sh` |
| Ошибка 429 при входе | сработало ограничение частоты Nginx, подождите около минуты |
| `failed to connect to the docker API ... no such file or directory` | служба Docker не запущена: `sudo systemctl enable --now docker.service` |
| `permission denied while trying to connect to the docker API` | пользователь не в группе `docker` или нет перелогина: `sudo usermod -aG docker $USER`, затем перелогин (временно `sudo`) |
| `Expected a string, but found a redirection` | в fish не работает `<<'EOF'`: создайте `.env` скриптом `./scripts/init-env.sh` |
| `port is already allocated` на 8080 | порт занят: `ss -ltnp \| grep 8080` |
| `/lab/` показывает 503 | контейнер остановлен: `docker compose start lab-web`, причина в `docker compose logs lab-web` |
| `app` не становится `healthy` | смотрите `docker compose logs app` |
