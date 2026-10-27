"""Тесты стыков между шаблонами, загрузчиком заданий и кодом backend.

FastAPI, SQLAlchemy и Argon2 не нужны: main.py и models.py разбираются как текст (модуль ast),
база для проверки загрузчика создаётся средствами sqlite3.

    python3 -m unittest discover -s tests -v
"""
import ast
import hashlib
import hmac
import importlib.util
import json
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"

try:
    import jinja2
except ImportError:          # pragma: no cover
    jinja2 = None

_spec = importlib.util.spec_from_file_location("seed_challenges", APP / "seed_challenges.py")
seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed)

MAIN_TREE = ast.parse((APP / "main.py").read_text(encoding="utf-8"))
MODELS_TREE = ast.parse((APP / "models.py").read_text(encoding="utf-8"))


def backend_routes():
    """{(метод, путь): {'required': {...}, 'optional': {...}}} по декораторам @app.get/@app.post."""
    routes = {}
    for node in ast.walk(MAIN_TREE):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name) and dec.func.value.id == "app"
                    and dec.func.attr in ("get", "post") and dec.args):
                form = {"required": set(), "optional": set()}
                args = node.args.args
                defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
                for arg, default in zip(args, defaults):
                    if (isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
                            and default.func.id == "Form"):
                        is_required = (default.args and isinstance(default.args[0], ast.Constant)
                                       and default.args[0].value is Ellipsis)
                        form["required" if is_required else "optional"].add(arg.arg)
                routes[(dec.func.attr.upper(), dec.args[0].value)] = form
    return routes


def norm(path):
    """/challenges/{challenge_id}/submit и /challenges/{{ c.id }}/submit -> /challenges/{}/submit"""
    return re.sub(r"\{\{.*?\}\}|\{[a-z_]+\}", "{}", path)


ROUTES = {(m, norm(p)): f for (m, p), f in backend_routes().items()}
TEMPLATES = sorted((APP / "templates").glob("*.html"))


class ContractTests(unittest.TestCase):
    def test_backend_routes_found(self):
        self.assertIn(("POST", "/challenges/{}/submit"), ROUTES)
        self.assertIn(("GET", "/leaderboard"), ROUTES)

    def test_every_post_form_matches_its_route(self):
        """Поля форм в шаблонах совпадают с параметрами Form(...) маршрутов backend."""
        checked = 0
        for tpl in TEMPLATES:
            html = tpl.read_text(encoding="utf-8")
            for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.S):
                attrs, body = match.groups()
                action = re.search(r'action="([^"]+)"', attrs).group(1)
                self.assertRegex(attrs, r'method="post"', "%s: форма %s не POST" % (tpl.name, action))
                names = set(re.findall(r'<(?:input|select|textarea)\b[^>]*\bname="([^"]+)"', body))
                targets = ["/login", "/register"] if action == "{{ action }}" else [norm(action)]
                for target in targets:
                    route = ROUTES.get(("POST", target))
                    self.assertIsNotNone(route, "%s: нет маршрута POST %s" % (tpl.name, target))
                    allowed = route["required"] | route["optional"]
                    self.assertFalse(names - allowed, "%s %s: лишние поля %s" % (tpl.name, target, names - allowed))
                    self.assertFalse(route["required"] - names, "%s %s: нет обязательных полей %s" % (tpl.name, target, route["required"] - names))
                checked += 1
        self.assertEqual(checked, 7)   # logout, вход/регистрация, смена пароля, флаг, 3 формы админки

    def test_internal_links_lead_to_routes(self):
        for tpl in TEMPLATES:
            html = tpl.read_text(encoding="utf-8")
            for href in re.findall(r'href="(/[^"#?]*)', html):
                if href.startswith("/static/"):
                    continue                                   # статику раздаёт Nginx
                self.assertIn(("GET", norm(href)), ROUTES, "%s: ссылка %s ведёт в никуда" % (tpl.name, href))

    def test_logout_is_post_with_csrf(self):
        base = (APP / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertNotIn('href="/logout"', base)
        self.assertRegex(base, r'action="/logout" method="post"><input type="hidden" name="csrf_token"')


@unittest.skipIf(jinja2 is None, "jinja2 не установлен")
class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(APP / "templates")), autoescape=True)
        cls.player = NS(username="alice", is_admin=False)
        cls.admin = NS(username="teacher", is_admin=True)
        cls.challenge = NS(id=1, title="WEB-01 Школьный портал", category="Web", difficulty="easy",
                           description="Найдите флаг", points=100, is_published=True, resource_url="/lab/")

    def render(self, name, user="player", **ctx):
        who = {"player": self.player, "admin": self.admin, None: None}[user]
        return self.env.get_template(name).render(user=who, csrf="TOKEN123", **ctx)

    def test_all_pages_render_with_backend_context(self):
        c = self.challenge
        pages = {
            "home.html": dict(challenges=[c]),
            "auth.html": dict(heading="Вход", action="/login"),
            "password.html": {},
            "challenges.html": dict(challenges=[c], solved_ids={1}),
            "challenge.html": dict(challenge=c, message="Верно! Решение записано"),
            "leaderboard.html": dict(scores=[NS(username="alice", score=100, last_solve=None)]),
            "profile.html": dict(solved=[NS(title="T", points=100, solved_at="2026-10-16 10:00")], score=100),
            "admin.html": dict(challenges=[c], attempts=[(NS(submitted_at="2026-10-16", is_correct=True), "alice", "T")]),
        }
        for name, ctx in pages.items():
            html = self.render(name, user="admin", **ctx)
            self.assertIn("CYBERARENA", html, name)
            self.assertIn("<main", html, name)

    def test_csrf_in_every_post_form(self):
        c = self.challenge
        for name, ctx in {"auth.html": dict(heading="Вход", action="/login"), "password.html": {},
                          "challenge.html": dict(challenge=c, message=""),
                          "admin.html": dict(challenges=[c], attempts=[])}.items():
            html = self.render(name, **ctx)
            forms = re.findall(r"<form\b.*?</form>", html, re.S)
            self.assertTrue(forms, name)
            for form in forms:
                self.assertIn('name="csrf_token" value="TOKEN123"', form, name)

    def test_catalog_status_and_escaping(self):
        evil = NS(id=2, title="<script>alert(1)</script>", category="Crypto", difficulty="medium",
                  description="<img src=x onerror=alert(1)>", points=150, is_published=True, resource_url=None)
        html = self.render("challenges.html", challenges=[self.challenge, evil], solved_ids={1})
        self.assertEqual(html.count(">Решено<"), 1)
        self.assertEqual(html.count(">Доступно<"), 1)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<img src=x", html)

    def test_resource_link_only_for_local_paths(self):
        bad = NS(**{**vars(self.challenge), "resource_url": "javascript:alert(1)"})
        self.assertNotIn("javascript:", self.render("challenge.html", challenge=bad, message=""))
        self.assertIn('href="/lab/"', self.render("challenge.html", challenge=self.challenge, message=""))

    def test_message_styles(self):
        ok = self.render("challenge.html", challenge=self.challenge, message="Верно! Решение записано")
        bad = self.render("challenge.html", challenge=self.challenge, message="Неверный флаг")
        self.assertIn('class="notice"', ok)
        self.assertIn('class="notice bad"', bad)

    def test_navigation_by_role(self):
        guest = self.render("home.html", user=None, challenges=[])
        self.assertIn("Регистрация", guest)
        self.assertNotIn('href="/admin"', guest)
        self.assertNotIn('action="/logout"', guest)
        self.assertNotIn('href="/admin"', self.render("home.html", challenges=[]))
        self.assertIn('href="/admin"', self.render("home.html", user="admin", challenges=[]))
        self.assertIn('action="/logout"', self.render("home.html", challenges=[]))

    def test_leaderboard_marks_current_user_and_handles_dates(self):
        import datetime
        scores = [NS(username="alice", score=250, last_solve=datetime.datetime(2026, 10, 16, 12, 30)),
                  NS(username="bob", score=0, last_solve=None)]
        html = self.render("leaderboard.html", scores=scores)
        self.assertIn("16.10 12:30", html)
        self.assertIn("—", html)
        self.assertEqual(html.count(">ВЫ<"), 1)
        self.assertIn("🥇", html)

    def test_no_flags_or_hashes_in_pages(self):
        c = self.challenge
        for name, ctx in {"challenges.html": dict(challenges=[c], solved_ids=set()),
                          "admin.html": dict(challenges=[c], attempts=[])}.items():
            html = self.render(name, user="admin", **ctx)
            self.assertNotIn("CTF{", html.replace('placeholder="CTF{...}"', "").replace("CTF{your_flag_here}", ""))


class SeedLoaderTests(unittest.TestCase):
    SECRET = "x" * 40
    FLAGS = {"WEB01_FLAG": "CTF{one}", "WEB02_FLAG": "CTF{two}", "CRYPTO01_FLAG": "CTF{three}"}

    def make_db(self, path):
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE challenges (
            id INTEGER PRIMARY KEY, title VARCHAR(140) NOT NULL, category VARCHAR(20) NOT NULL,
            difficulty VARCHAR(20) NOT NULL, description TEXT NOT NULL, points INTEGER NOT NULL,
            flag_hash VARCHAR(64) NOT NULL, is_published BOOLEAN NOT NULL, resource_url VARCHAR(300))""")
        return conn

    def items(self):
        return json.loads((APP / "seed" / "challenges.json").read_text(encoding="utf-8"))

    def test_hash_formula_equals_backend(self):
        """Берём настоящую hash_flag() из main.py и сравниваем с формулой загрузчика."""
        fn = next(n for n in MAIN_TREE.body if isinstance(n, ast.FunctionDef) and n.name == "hash_flag")
        ns = {"hashlib": hashlib, "hmac": hmac, "SECRET_KEY": self.SECRET}
        exec(compile(ast.Module([fn], []), "main.py", "exec"), ns)
        for flag in ("CTF{abc}", "CTF{идор}", self.FLAGS["WEB01_FLAG"]):
            self.assertEqual(ns["hash_flag"](flag), seed.hash_flag(self.SECRET, flag))

    def test_loader_columns_exist_in_backend_model(self):
        cls = next(n for n in MODELS_TREE.body if isinstance(n, ast.ClassDef) and n.name == "Challenge")
        model_columns = {n.target.id for n in cls.body if isinstance(n, ast.AnnAssign)}
        self.assertLessEqual(set(seed.COLUMNS), model_columns)

    def test_seed_values_accepted_by_backend_validation(self):
        for item in self.items():
            self.assertIn(item["category"], ("Web", "Crypto"))
            self.assertIn(item["difficulty"], ("easy", "medium", "hard"))
            self.assertTrue(1 <= item["points"] <= 1000)
            self.assertLessEqual(len(item["title"]), 140)
            self.assertTrue(item["resource_url"].startswith("/"))

    def test_load_is_idempotent_and_keeps_publication_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = self.make_db(Path(tmp) / "t.db")
            self.assertEqual(seed.load_challenges(conn, self.items(), self.FLAGS, self.SECRET), (3, 0))
            conn.execute("UPDATE challenges SET is_published = 0 WHERE id = 1")
            self.assertEqual(seed.load_challenges(conn, self.items(), self.FLAGS, self.SECRET), (0, 3))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM challenges").fetchone()[0], 3)
            self.assertEqual(conn.execute("SELECT is_published FROM challenges WHERE id = 1").fetchone()[0], 0)
            row = conn.execute("SELECT flag_hash FROM challenges WHERE title LIKE 'WEB-01%'").fetchone()
            self.assertEqual(row[0], seed.hash_flag(self.SECRET, self.FLAGS["WEB01_FLAG"]))
            dump = " ".join(str(r) for r in conn.execute("SELECT * FROM challenges"))
            self.assertNotIn("CTF{", dump)                      # в базе только хеши
            conn.close()

    def test_errors_are_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = sqlite3.connect(Path(tmp) / "e.db")
            with self.assertRaisesRegex(RuntimeError, "сначала запустите платформу"):
                seed.load_challenges(empty, self.items(), self.FLAGS, self.SECRET)
            conn = self.make_db(Path(tmp) / "t.db")
            with self.assertRaisesRegex(ValueError, "WEB01_FLAG"):
                seed.load_challenges(conn, self.items(), {**self.FLAGS, "WEB01_FLAG": "bad"}, self.SECRET)

    def test_sqlite_path(self):
        self.assertEqual(seed.sqlite_path("sqlite:////data/cyberarena.db"), "/data/cyberarena.db")
        self.assertEqual(seed.sqlite_path("sqlite:///./cyberarena.db"), "./cyberarena.db")
        with self.assertRaises(ValueError):
            seed.sqlite_path("postgresql://x")


class ConfigTests(unittest.TestCase):
    def test_env_example_placeholders_are_unusable(self):
        env = dict(l.split("=", 1) for l in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
                   if "=" in l and not l.startswith("#"))
        self.assertLess(len(env["SECRET_KEY"]), 32)           # платформа не стартует с заглушкой
        self.assertLess(len(env["ADMIN_PASSWORD"]), 12)
        for name in ("WEB01_FLAG", "WEB02_FLAG", "CRYPTO01_FLAG"):
            self.assertIn(name, env)

    def test_platform_container_gets_no_task_flags(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml не установлен")
        compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
        app = compose["services"]["app"]
        self.assertNotIn("env_file", app)
        self.assertFalse([k for k in app["environment"] if "FLAG" in k])
        self.assertIn("WEB01_FLAG", compose["services"]["lab-web"]["environment"])

    def test_scripts_use_lf_and_gitattributes_forces_it(self):
        """Git на Windows подставляет CRLF и ломает bash-скрипты: нужны LF и .gitattributes."""
        for path in list((ROOT / "scripts").glob("*.sh")) + [ROOT / "nginx" / "nginx.conf", ROOT / ".env.example"]:
            self.assertNotIn(b"\r\n", path.read_bytes(), "%s содержит CRLF" % path.name)
        attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("*.sh text eol=lf", attrs)
        self.assertIn("*.conf text eol=lf", attrs)


    def test_nginx_serves_static_and_limits_forms(self):
        conf = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
        self.assertEqual(conf.count("{"), conf.count("}"))
        for needle in ("location /static/", "limit_req_zone", "limit_req_status 429", "POST:/(login|register)",
                       "/challenges/[0-9]+/submit", "error_page 502 503 504 = @lab_down"):
            self.assertIn(needle, conf)


if __name__ == "__main__":
    unittest.main()
