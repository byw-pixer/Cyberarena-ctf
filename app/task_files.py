"""Описания заданий и генерация материалов из флагов развёртывания."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import shutil
from pathlib import Path

# Только латиница, цифры, «_» и «-»: так флаг одинаково работает в base64 и в шифре Виженера.
# Это подмножество формата, который принимает платформа (CTF{1..160 символов без скобок и переводов строк}).
FLAG_RE = re.compile(r"^CTF\{[A-Za-z0-9_\-]{1,150}\}$")

FLAG_NAMES = ("WEB01_FLAG", "WEB02_FLAG", "CRYPTO01_FLAG")

CRYPTO_KEY = "cyberarena"   # ключ шифра: название платформы (сказано в условии задания)
PLAINTEXT = "Intercepted note. The secret you are looking for is {flag}"

# Задания. Поле code стоит в начале названия и служит стабильным идентификатором:
# по нему init_db.py находит задание, чтобы обновить его флаг.
CHALLENGES = [
    {
        "code": "WEB-01",
        "title": "WEB-01 Школьный портал",
        "category": "Web",
        "difficulty": "easy",
        "points": 100,
        "flag_env": "WEB01_FLAG",
        "resource_url": "/lab/",
        "description": (
            "Школьный портал заметок. Вы вошли как student3 и видите свою заметку. "
            "Разработчики говорят, что оставили на портале закрытую тестовую страницу "
            "с секретом. Найдите её и получите флаг. Работайте только с лабораторией /lab/."
        ),
    },
    {
        "code": "WEB-02",
        "title": "WEB-02 Сейф на JavaScript",
        "category": "Web",
        "difficulty": "easy",
        "points": 150,
        "flag_env": "WEB02_FLAG",
        "resource_url": "/static/tasks/web02/index.html",
        "description": (
            "Страница просит код доступа, а проверка выполняется прямо в браузере. "
            "Изучите страницу и подключённые к ней файлы, найдите ожидаемый код. "
            "Он и есть флаг."
        ),
    },
    {
        "code": "CRYPTO-01",
        "title": "CRYPTO-01 Перехваченная записка",
        "category": "Crypto",
        "difficulty": "medium",
        "points": 150,
        "flag_env": "CRYPTO01_FLAG",
        "resource_url": "/static/tasks/crypto01/cipher.txt",
        "description": (
            "Скачайте шифротекст и расшифруйте записку. Подсказка: шифр использует "
            "повторяющийся ключ, а ключ это название нашей платформы на английском "
            "языке строчными буквами. Знаки препинания не шифруются."
        ),
    },
]

VAULT_JS = """// Файл создаётся автоматически при старте платформы. Вручную не редактировать.
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


class ConfigError(ValueError):
    """Ошибка настройки (понятное сообщение для оператора)."""


def load_flags(environ, previous=None):
    flags = {}
    for name in FLAG_NAMES:
        value = (environ.get(name) or "").strip()
        if value and not FLAG_RE.fullmatch(value):
            raise ConfigError(f"{name}: нужен флаг формата CTF с латиницей, цифрами, _ или - внутри скобок")
        flags[name] = value or (previous or {}).get(name) or "CTF{" + secrets.token_hex(16) + "}"
    return flags


def hash_flag(secret, flag):
    """Формула платформы (main.py): HMAC-SHA256 с ключом SECRET_KEY."""
    return hmac.new(secret.encode(), flag.encode(), hashlib.sha256).hexdigest()


def vigenere(text, key, decrypt=False):
    """Шифр Виженера: сдвигаются только латинские буквы, остальные символы остаются на месте."""
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
    """vault.js: флаг разбит на куски по 8 символов и записан в base64."""
    chunks = [flag[i:i + 8] for i in range(0, len(flag), 8)]
    parts = [base64.b64encode(c.encode("ascii")).decode("ascii") for c in chunks]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vault.js").write_text(VAULT_JS.replace("__PARTS__", json.dumps(parts)), encoding="utf-8")


def build_crypto01(flag, out_dir, key=CRYPTO_KEY):
    """cipher.txt: записка с флагом, зашифрованная шифром Виженера."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cipher = vigenere(PLAINTEXT.format(flag=flag), key)
    (out_dir / "cipher.txt").write_text(cipher + "\n", encoding="utf-8")


def prepare_static(src_dir, dst_dir, flags):
    """Копирует статику образа в рабочий каталог и создаёт файлы заданий из флагов."""
    dst_dir = Path(dst_dir)
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    build_web02(flags["WEB02_FLAG"], dst_dir / "tasks" / "web02")
    build_crypto01(flags["CRYPTO01_FLAG"], dst_dir / "tasks" / "crypto01")
