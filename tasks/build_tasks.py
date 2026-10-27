#!/usr/bin/env python3
"""Генератор учебных заданий CyberArena (роль «Автор заданий / QA»).

Берёт флаги (переменные окружения > .env > .env.example) и пересоздаёт:
  app/static/tasks/web02/vault.js        WEB-02: флаг в виде base64-кусочков
  app/static/tasks/crypto01/cipher.txt   CRYPTO-01: шифротекст (шифр с повторяющимся ключом)
  app/seed/challenges.json               карточки заданий для загрузки в БД (без флагов и без хешей)

Флаг WEB-01 сюда не попадает: его читает контейнер лаборатории из WEB01_FLAG.
Хеши флагов считает загрузчик app/seed_challenges.py по формуле платформы (HMAC-SHA256 с SECRET_KEY).

Запуск:  python3 tasks/build_tasks.py
"""
import base64
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FLAG_NAMES = ("WEB01_FLAG", "WEB02_FLAG", "CRYPTO01_FLAG")
FLAG_RE = re.compile(r"^CTF\{[A-Za-z0-9_\-]+\}$")
DEFAULT_KEY = "cyberarena"
PLAINTEXT = "Intercepted note. The secret you are looking for is {flag}"

VAULT_JS = """// Файл сгенерирован tasks/build_tasks.py. Вручную не редактировать.
(function () {
  var parts = __PARTS__;

  function expected() {
    var s = "";
    for (var i = 0; i < parts.length; i++) { s += atob(parts[i]); }
    return s;
  }

  var form = document.getElementById("vault-form");
  var input = document.getElementById("code");
  var result = document.getElementById("result");

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (input.value.trim() === expected()) {
      result.textContent = "Доступ разрешён. Этот код и есть флаг: сдайте его на платформе.";
    } else {
      result.textContent = "Неверный код доступа.";
    }
  });
})();
"""

CHALLENGES = [
    {
        "slug": "WEB-01",
        "title": "WEB-01 Школьный портал",
        "category": "Web",
        "difficulty": "easy",
        "points": 100,
        "flag": "WEB01_FLAG",
        "resource_url": "/lab/",
        "description": (
            "Школьный портал заметок. Вы вошли как student3 и видите свою заметку. "
            "Разработчики говорят, что оставили на портале закрытую тестовую страницу "
            "с секретом. Найдите её и получите флаг. Работайте только с лабораторией /lab/."
        ),
    },
    {
        "slug": "WEB-02",
        "title": "WEB-02 Сейф на JavaScript",
        "category": "Web",
        "difficulty": "easy",
        "points": 150,
        "flag": "WEB02_FLAG",
        "resource_url": "/static/tasks/web02/index.html",
        "description": (
            "Страница просит код доступа, а проверка выполняется прямо в браузере. "
            "Изучите страницу и подключённые к ней файлы, найдите ожидаемый код. "
            "Он и есть флаг."
        ),
    },
    {
        "slug": "CRYPTO-01",
        "title": "CRYPTO-01 Перехваченная записка",
        "category": "Crypto",
        "difficulty": "medium",
        "points": 150,
        "flag": "CRYPTO01_FLAG",
        "resource_url": "/static/tasks/crypto01/cipher.txt",
        "description": (
            "Скачайте шифротекст и расшифруйте записку. Подсказка: шифр использует "
            "повторяющийся ключ, а ключ это название нашей платформы на английском "
            "языке строчными буквами. Знаки препинания не шифруются."
        ),
    },
]


def parse_env_file(path):
    values = {}
    if not Path(path).is_file():
        return values
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip().strip("\"'")
    return values


def load_flags(root=ROOT, environ=None):
    """Возвращает (флаги, ключ шифра). Приоритет: окружение > .env > .env.example."""
    environ = os.environ if environ is None else environ
    merged = {}
    for name in (".env.example", ".env"):
        merged.update(parse_env_file(Path(root) / name))
    for name in FLAG_NAMES + ("CRYPTO01_KEY",):
        if environ.get(name):
            merged[name] = environ[name]
    flags = {}
    for name in FLAG_NAMES:
        value = merged.get(name, "")
        if not FLAG_RE.match(value):
            raise ValueError(
                "%s не задан или неверного формата (нужно CTF{буквы_цифры_-}): %r" % (name, value)
            )
        flags[name] = value
    return flags, merged.get("CRYPTO01_KEY", DEFAULT_KEY)


def vigenere(text, key, decrypt=False):
    shifts = [ord(c) - 97 for c in key.lower() if "a" <= c <= "z"]
    if not shifts:
        raise ValueError("ключ шифра должен содержать латинские буквы")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            base = 65 if ch.isupper() else 97
            shift = shifts[i % len(shifts)] * (-1 if decrypt else 1)
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def build_web02(flag, out_dir):
    chunks = [flag[i:i + 8] for i in range(0, len(flag), 8)]
    parts = [base64.b64encode(c.encode("ascii")).decode("ascii") for c in chunks]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vault.js").write_text(
        VAULT_JS.replace("__PARTS__", json.dumps(parts)), encoding="utf-8"
    )


def build_crypto01(flag, key, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cipher = vigenere(PLAINTEXT.format(flag=flag), key)
    (out_dir / "cipher.txt").write_text(cipher + "\n", encoding="utf-8")


def build_seed(seed_path):
    """Карточки заданий без флагов и без хешей (хеши считает app/seed_challenges.py)."""
    items = []
    for ch in CHALLENGES:
        items.append({
            "title": ch["title"],
            "category": ch["category"],
            "difficulty": ch["difficulty"],
            "description": ch["description"],
            "points": ch["points"],
            "resource_url": ch["resource_url"],
            "is_published": True,
            "flag_env": ch["flag"],
        })
    seed_path = Path(seed_path)
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def build_all(flags, key, static_dir, seed_path):
    static_dir = Path(static_dir)
    build_web02(flags["WEB02_FLAG"], static_dir / "tasks" / "web02")
    build_crypto01(flags["CRYPTO01_FLAG"], key, static_dir / "tasks" / "crypto01")
    build_seed(seed_path)


def main():
    try:
        flags, key = load_flags()
    except ValueError as err:
        print("Ошибка:", err, file=sys.stderr)
        return 1
    build_all(flags, key, ROOT / "app" / "static", ROOT / "app" / "seed" / "challenges.json")
    print("Готово: vault.js, cipher.txt и app/seed/challenges.json пересозданы.")
    print("WEB-01 флаг читает контейнер лаборатории из WEB01_FLAG (.env).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
