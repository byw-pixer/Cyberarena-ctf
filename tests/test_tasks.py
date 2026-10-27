"""Автотесты заданий CyberArena (роль «Автор заданий / QA»).

Запуск из корня репозитория, без Docker и без внешних библиотек:
    python3 -m unittest discover -s tests -v

Что проверяется:
  - WEB-01: лаборатория отвечает, уязвимость IDOR работает как задумано,
    свои данные и главная страница флага не содержат, мусорные запросы не роняют сервер
  - WEB-02 и CRYPTO-01: из выданных файлов флаг восстанавливается, а в открытом виде его нет
  - seed: карточки заданий без флагов и без хешей
  - публичные файлы платформы флагов не содержат
"""
import base64
import hashlib
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import importlib.util

sys.path.insert(0, str(ROOT / "tasks"))
import build_tasks as bt         # tasks/build_tasks.py

# lab/app.py загружаем по пути: имя «app» совпадает с папкой платформы app/
_spec = importlib.util.spec_from_file_location("lab_app", ROOT / "lab" / "app.py")
lab_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_app)    # lab/app.py (WEB-01)

TEST_FLAGS = {
    "WEB01_FLAG": "CTF{test_web01_flag}",
    "WEB02_FLAG": "CTF{test_web02_flag}",
    "CRYPTO01_FLAG": "CTF{test_crypto_flag}",
}


def decode_vault(vault_js_text):
    parts = json.loads(re.search(r"var parts = (\[.*?\]);", vault_js_text, re.S).group(1))
    return "".join(base64.b64decode(p).decode("ascii") for p in parts)


class Web01Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old = os.environ.get("WEB01_FLAG")
        os.environ["WEB01_FLAG"] = TEST_FLAGS["WEB01_FLAG"]
        cls.server = lab_app.make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if cls._old is None:
            os.environ.pop("WEB01_FLAG", None)
        else:
            os.environ["WEB01_FLAG"] = cls._old

    def get(self, path):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path), timeout=5) as r:
                return r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8")

    def test_health(self):
        self.assertEqual(self.get("/health"), (200, "ok"))

    def test_home_has_no_flag_and_uses_relative_links(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertNotIn("CTF{", body)
        self.assertIn('href="notes?id=3"', body)          # ссылка относительная: приложение живёт под /lab/
        self.assertNotIn('href="/', body)

    def test_own_note_has_no_flag(self):
        status, body = self.get("/notes?id=3")
        self.assertEqual(status, 200)
        self.assertNotIn("CTF{", body)

    def test_idor_reveals_flag(self):
        """Намеренная уязвимость: чужая заметка №1 доступна без проверки владельца."""
        status, body = self.get("/notes?id=1")
        self.assertEqual(status, 200)
        self.assertIn(TEST_FLAGS["WEB01_FLAG"], body)

    def test_other_users_note_is_open_too(self):
        status, body = self.get("/notes?id=2")
        self.assertEqual(status, 200)
        self.assertIn("teacher", body)

    def test_missing_and_invalid_ids(self):
        self.assertEqual(self.get("/notes?id=999")[0], 404)
        self.assertEqual(self.get("/notes?id=abc")[0], 400)
        self.assertEqual(self.get("/notes?id=1%20OR%201=1")[0], 400)
        self.assertEqual(self.get("/notes")[0], 400)

    def test_unknown_paths_do_not_leak_files(self):
        for path in ("/etc/passwd", "/app.py", "/../app.py", "/%2e%2e/%2e%2e/etc/passwd"):
            status, body = self.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn("root:", body)
            self.assertNotIn("import os", body)

    def test_raw_dotdot_request_is_not_served(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/../../etc/passwd")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 404)
        self.assertNotIn(b"root:", resp.read())
        conn.close()

    def test_html_is_escaped(self):
        self.assertNotIn("<script", self.get("/notes?id=2")[1])


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.static = Path(self.tmp.name) / "static"
        self.seed = Path(self.tmp.name) / "seed.json"
        bt.build_all(TEST_FLAGS, bt.DEFAULT_KEY, self.static, self.seed)

    def tearDown(self):
        self.tmp.cleanup()

    def test_web02_flag_recoverable_but_not_plaintext(self):
        js = (self.static / "tasks" / "web02" / "vault.js").read_text(encoding="utf-8")
        self.assertEqual(decode_vault(js), TEST_FLAGS["WEB02_FLAG"])
        self.assertNotIn(TEST_FLAGS["WEB02_FLAG"], js)
        self.assertNotIn("CTF{", js)

    def test_crypto01_decrypts_with_right_key_only(self):
        cipher = (self.static / "tasks" / "crypto01" / "cipher.txt").read_text(encoding="utf-8").strip()
        self.assertNotIn("CTF{", cipher)
        self.assertNotIn(TEST_FLAGS["CRYPTO01_FLAG"], cipher)
        self.assertIn(TEST_FLAGS["CRYPTO01_FLAG"], bt.vigenere(cipher, bt.DEFAULT_KEY, decrypt=True))
        self.assertNotIn(TEST_FLAGS["CRYPTO01_FLAG"], bt.vigenere(cipher, "wrongkey", decrypt=True))

    def test_vigenere_roundtrip_keeps_non_letters(self):
        text = "Hello, World! 123 {a_b-c}"
        enc = bt.vigenere(text, "key")
        self.assertEqual(bt.vigenere(enc, "key", decrypt=True), text)
        self.assertEqual([c for c in enc if not c.isalpha()], [c for c in text if not c.isalpha()])

    def test_seed_has_no_flags_and_no_hashes(self):
        raw = self.seed.read_text(encoding="utf-8")
        for flag in TEST_FLAGS.values():
            self.assertNotIn(flag, raw)
        self.assertNotIn("CTF{", raw)
        self.assertNotIn("flag_hash", raw)
        items = json.loads(raw)
        self.assertEqual([i["points"] for i in items], [100, 150, 150])
        self.assertEqual([i["category"] for i in items], ["Web", "Web", "Crypto"])
        self.assertEqual([i["difficulty"] for i in items], ["easy", "easy", "medium"])
        self.assertEqual([i["flag_env"] for i in items], ["WEB01_FLAG", "WEB02_FLAG", "CRYPTO01_FLAG"])
        self.assertEqual(len({i["title"] for i in items}), 3)          # загрузчик ищет задания по названию

    def test_bad_flag_format_is_rejected(self):
        with self.assertRaises(ValueError):
            bt.load_flags(root=self.tmp.name, environ={"WEB01_FLAG": "flag{wrong}"})


class RepositoryTests(unittest.TestCase):
    """Проверки реальных файлов репозитория с флагами из .env (или .env.example)."""

    @classmethod
    def setUpClass(cls):
        cls.flags, cls.key = bt.load_flags()

    def test_committed_artifacts_match_flags(self):
        js = (ROOT / "app/static/tasks/web02/vault.js").read_text(encoding="utf-8")
        self.assertEqual(decode_vault(js), self.flags["WEB02_FLAG"],
                         "vault.js устарел: запустите python3 tasks/build_tasks.py")
        cipher = (ROOT / "app/static/tasks/crypto01/cipher.txt").read_text(encoding="utf-8").strip()
        self.assertIn(self.flags["CRYPTO01_FLAG"], bt.vigenere(cipher, self.key, decrypt=True),
                      "cipher.txt устарел: запустите python3 tasks/build_tasks.py")
        with tempfile.TemporaryDirectory() as tmp:
            expected = Path(tmp) / "challenges.json"
            bt.build_seed(expected)
            self.assertEqual(
                json.loads((ROOT / "app/seed/challenges.json").read_text(encoding="utf-8")),
                json.loads(expected.read_text(encoding="utf-8")),
                "app/seed/challenges.json устарел: запустите python3 tasks/build_tasks.py")

    def test_flags_not_in_public_platform_files(self):
        public = [
            "app/static/index.html", "app/static/tasks/web02/index.html", "app/static/tasks/web02/vault.js",
            "app/static/tasks/crypto01/cipher.txt", "app/main.py", "app/seed/challenges.json", "app/seed_challenges.py",
            "compose.yaml", "nginx/nginx.conf", "README.md", "docs/INFRASTRUCTURE.md",
        ]
        for rel in public:
            path = ROOT / rel
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for name, flag in self.flags.items():
                self.assertNotIn(flag, text, "флаг %s найден в %s" % (name, rel))

    def test_env_file_is_gitignored(self):
        self.assertIn(".env", (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())


if __name__ == "__main__":
    unittest.main()
