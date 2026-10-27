"""WEB-01 «Школьный портал заметок»: учебное приложение с НАМЕРЕННОЙ ошибкой
разграничения доступа (IDOR). Уязвимо только внутри изолированной лаборатории.

Контракт с DevOps:
  - порт 5000, GET /health -> 200
  - приложение живёт под префиксом /lab/ (Nginx срезает его), поэтому все
    ссылки внутри ОТНОСИТЕЛЬНЫЕ
  - на диск ничего не пишет, зависимостей нет (только стандартная библиотека)
  - флаг берётся из переменной окружения WEB01_FLAG (задаётся в .env)

Сценарий: пользователь student3 видит свою заметку №3 (notes?id=3). Заметка №1
(«тестовая страница» администратора) нигде не показана, но сервер отдаёт её
любому, кто подставит id=1: проверки владельца нет.
"""
import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CURRENT_USER = {"id": 3, "name": "student3"}
PLACEHOLDER_FLAG = "CTF{flag_not_configured}"


def get_flag():
    return os.environ.get("WEB01_FLAG") or PLACEHOLDER_FLAG


def get_notes():
    return {
        1: {
            "owner": "admin",
            "title": "ТЕСТОВАЯ СТРАНИЦА (удалить перед релизом)",
            "body": "Служебная проверка. Секрет: " + get_flag(),
        },
        2: {
            "owner": "teacher",
            "title": "Расписание консультаций",
            "body": "Вторник и четверг, кабинет 214.",
        },
        3: {
            "owner": "student3",
            "title": "Мои заметки",
            "body": "Купить тетрадь. Подготовиться к контрольной.",
        },
    }


PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body{{margin:0;font-family:system-ui,sans-serif;background:#0b1424;color:#e6edf7}}
  main{{max-width:640px;margin:48px auto;padding:0 20px}}
  h1{{font-size:24px}} a{{color:#8fd3ff}}
  .card{{background:#12203a;border:1px solid #223556;border-radius:10px;padding:16px 20px}}
  .muted{{color:#8a9bb8;font-size:14px}}
</style></head>
<body><main>{body}</main></body></html>
"""


def render(title, body):
    return PAGE.format(title=html.escape(title), body=body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SchoolPortal"
    sys_version = ""

    def _send(self, status, body, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, text):
        body = ("<h1>%s</h1><p><a href=\"./\">На главную</a></p>" % html.escape(text))
        self._send(status, render("Ошибка", body))

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            self._send(200, b"ok", "text/plain")
        elif url.path == "/":
            self._home()
        elif url.path == "/notes":
            self._note(parse_qs(url.query))
        else:
            self._error(404, "Страница не найдена")

    def _home(self):
        body = (
            "<h1>Школьный портал заметок</h1>"
            "<p>Вы вошли как <b>%s</b>.</p>"
            "<div class=\"card\"><p>Ваши заметки:</p>"
            "<ul><li><a href=\"notes?id=%d\">Заметка №%d</a></li></ul></div>"
            % (html.escape(CURRENT_USER["name"]), CURRENT_USER["id"], CURRENT_USER["id"])
        )
        self._send(200, render("Школьный портал", body))

    def _note(self, query):
        raw = (query.get("id") or [""])[0]
        if not raw.isdigit():
            return self._error(400, "Некорректный номер заметки")
        note = get_notes().get(int(raw))
        if note is None:
            return self._error(404, "Заметка не найдена")
        # НАМЕРЕННАЯ ОШИБКА: нет проверки note["owner"] == CURRENT_USER["name"].
        # Исправление: вернуть 403, если заметка принадлежит другому пользователю.
        body = (
            "<h1>%s</h1><div class=\"card\"><p>%s</p>"
            "<p class=\"muted\">Автор: %s · заметка №%s</p></div>"
            "<p><a href=\"./\">← На главную</a></p>"
            % (html.escape(note["title"]), html.escape(note["body"]),
               html.escape(note["owner"]), raw)
        )
        self._send(200, render(note["title"], body))


def make_server(host="0.0.0.0", port=5000):
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    if get_flag() == PLACEHOLDER_FLAG:
        print("ВНИМАНИЕ: WEB01_FLAG не задан, используется заглушка", file=sys.stderr)
    make_server().serve_forever()
