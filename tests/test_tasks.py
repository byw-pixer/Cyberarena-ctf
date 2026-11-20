"""Автотесты заданий CyberArena (без Docker и без внешних библиотек).

    python3 -m unittest discover -s tests -p "test_[tis]*.py" -v     # или просто: pytest -q

Что проверяется:
  - WEB-01: уязвимость IDOR работает как задумано, свои данные и главная флага не содержат,
    мусорные запросы не роняют сервер и не отдают файлы
  - WEB-02 и CRYPTO-01: флаг восстанавливается из выданных файлов, а в открытом виде его там нет
  - генерируемые флаги корректны, лаборатория читает предоставленный ей материал
  - шаблоны и публичные файлы не содержат тестовых ответов
"""
import base64
import http.client
import importlib.util
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
sys.path.insert(0, str(ROOT / "app"))
import task_files as tf          # app/task_files.py

# lab/app.py загружаем по пути: имя «app» совпадает с папкой платформы app/
_spec = importlib.util.spec_from_file_location("lab_app", ROOT / "lab" / "app.py")
lab_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_app)

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
        cls._old = os.environ.get("WEB01_FLAG_FILE")
        cls.directory = tempfile.TemporaryDirectory()
        flag_path = Path(cls.directory.name) / "web01.flag"
        flag_path.write_text(TEST_FLAGS["WEB01_FLAG"])
        os.environ["WEB01_FLAG_FILE"] = str(flag_path)
        cls.server = lab_app.make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if cls._old is None:
            os.environ.pop("WEB01_FLAG_FILE", None)
        else:
            os.environ["WEB01_FLAG_FILE"] = cls._old
        cls.directory.cleanup()

    def get(self, path):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path), timeout=5) as r:
                return r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8")

    def test_health(self):
        self.assertEqual(self.get("/health"), (200, "ok"))

    def test_head_has_headers_without_a_body(self):
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/", method="HEAD")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertGreater(int(response.headers["Content-Length"]), 0)
            self.assertEqual(response.read(), b"")

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

    def test_missing_material_does_not_use_a_default_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ["WEB01_FLAG_FILE"]
            os.environ["WEB01_FLAG_FILE"] = str(Path(directory) / "missing")
            try:
                self.assertEqual(self.get("/health")[0], 503)
                with self.assertRaises(FileNotFoundError):
                    lab_app.get_flag()
            finally:
                os.environ["WEB01_FLAG_FILE"] = previous


class TaskFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "static"
        tf.prepare_static(ROOT / "app" / "static", self.out, TEST_FLAGS)

    def tearDown(self):
        self.tmp.cleanup()

    def test_prepare_static_creates_all_files(self):
        for rel in ("style.css", "tasks/web02/index.html", "tasks/web02/vault.js", "tasks/crypto01/cipher.txt"):
            self.assertTrue((self.out / rel).is_file(), rel)

    def test_web02_flag_recoverable_but_not_plaintext(self):
        js = (self.out / "tasks/web02/vault.js").read_text(encoding="utf-8")
        self.assertEqual(decode_vault(js), TEST_FLAGS["WEB02_FLAG"])
        self.assertNotIn("CTF{", js)

    def test_crypto01_decrypts_with_right_key_only(self):
        cipher = (self.out / "tasks/crypto01/cipher.txt").read_text(encoding="utf-8").strip()
        self.assertNotIn("CTF{", cipher)
        self.assertIn(TEST_FLAGS["CRYPTO01_FLAG"], tf.vigenere(cipher, tf.CRYPTO_KEY, decrypt=True))
        self.assertNotIn(TEST_FLAGS["CRYPTO01_FLAG"], tf.vigenere(cipher, "wrongkey", decrypt=True))

    def test_no_flag_in_generated_static_files(self):
        for path in self.out.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="ignore")
                for flag in TEST_FLAGS.values():
                    self.assertNotIn(flag, text, path.name)

    def test_vigenere_roundtrip_keeps_non_letters(self):
        text = "Hello, World! 123 {a_b-c}"
        enc = tf.vigenere(text, "key")
        self.assertEqual(tf.vigenere(enc, "key", decrypt=True), text)
        self.assertEqual([c for c in enc if not c.isalpha()], [c for c in text if not c.isalpha()])


class FlagConfigTests(unittest.TestCase):
    def test_empty_environment_reuses_persisted_flags(self):
        self.assertEqual(tf.load_flags({"WEB01_FLAG": "  "}, TEST_FLAGS), TEST_FLAGS)
        self.assertNotEqual(tf.load_flags({}), tf.load_flags({}))

    def test_env_overrides_defaults(self):
        flags = tf.load_flags({"WEB02_FLAG": "CTF{custom_flag}"}, TEST_FLAGS)
        self.assertEqual(flags["WEB02_FLAG"], "CTF{custom_flag}")
        self.assertEqual(flags["WEB01_FLAG"], TEST_FLAGS["WEB01_FLAG"])

    def test_bad_format_is_rejected_with_flag_name(self):
        for bad in ("flag{x}", "CTF{}", "CTF{русский}", "CTF{a b}", "CTF{" + "a" * 200 + "}"):
            with self.assertRaisesRegex(tf.ConfigError, "WEB01_FLAG"):
                tf.load_flags({"WEB01_FLAG": bad})

    def test_generated_flags_are_valid_and_distinct(self):
        flags = tf.load_flags({})
        self.assertEqual(len(set(flags.values())), 3)
        for flag in flags.values():
            self.assertRegex(flag, tf.FLAG_RE)

    def test_lab_uses_only_the_material_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "web01.flag"
            path.write_text(TEST_FLAGS["WEB01_FLAG"])
            from unittest.mock import patch
            with patch.dict(os.environ, {"WEB01_FLAG_FILE": str(path)}):
                self.assertEqual(lab_app.get_flag(), TEST_FLAGS["WEB01_FLAG"])


class RepositoryTests(unittest.TestCase):
    def test_default_flags_not_in_public_files(self):
        """Демонстрационные флаги не должны быть в документации, шаблонах и публичных данных."""
        public = ["README.md", "compose.yaml", ".env.example", "nginx/compose.conf", "nginx/nginx.conf",
                  "app/static/index.html", "app/static/style.css", "app/static/tasks/web02/index.html"]
        public += [str(p.relative_to(ROOT)) for p in (ROOT / "app" / "templates").glob("*")]
        public += [str(p.relative_to(ROOT)) for p in (ROOT / "docs").glob("*.md")]
        for rel in public:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="ignore")
            for name, flag in TEST_FLAGS.items():
                self.assertNotIn(flag, text, "флаг %s найден в %s" % (name, rel))

    def test_no_teacher_folder_or_references(self):
        self.assertFalse((ROOT / "teacher").exists())
        skip = {".git", ".venv", "__pycache__", ".pytest_cache"}
        for path in ROOT.rglob("*"):
            if any(part in skip for part in path.parts) or not path.is_file():
                continue
            self.assertNotIn("teacher", [p.lower() for p in path.relative_to(ROOT).parts[:-1]], str(path))
            if path.suffix in (".md", ".py", ".yaml", ".conf", ".html", ".txt", ".example") or path.name == "Dockerfile":
                if path.name == "test_tasks.py":
                    continue
                self.assertNotIn("teacher/", path.read_text(encoding="utf-8", errors="ignore"), str(path))

    def test_no_bash_scripts_required_for_launch(self):
        scripts = [p.name for p in ROOT.rglob("*.sh") if ".venv" not in p.parts and ".git" not in p.parts]
        self.assertEqual(scripts, [], "в репозитории остались bash-скрипты: %s" % scripts)


if __name__ == "__main__":
    unittest.main()
