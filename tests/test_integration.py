"""Тесты стыков между шаблонами, инициализацией и кодом backend.

FastAPI, SQLAlchemy и Argon2 для большинства тестов не нужны: main.py и models.py разбираются как текст
(модуль ast). Тесты с реальной базой выполняются, если библиотеки установлены, иначе пропускаются.

    python3 -m unittest discover -s tests -p "test_[tis]*.py" -v     # или просто: pytest -q
"""
import ast
import hashlib
import hmac
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
sys.path.insert(0, str(APP))

try:
    import jinja2
except ImportError:          # pragma: no cover
    jinja2 = None

import init_db
import task_files as tf

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
                if href.startswith("/static/") or href.startswith("/lab"):
                    continue                                   # /static/ раздаёт платформа, /lab/ лаборатория
                self.assertIn(("GET", norm(href)), ROUTES, "%s: ссылка %s ведёт в никуда" % (tpl.name, href))

    def test_logout_is_post_with_csrf(self):
        base = (APP / "templates" / "base.html").read_text(encoding="utf-8")
        self.assertNotIn('href="/logout"', base)
        self.assertRegex(base, r'action="/logout" method="post"><input type="hidden" name="csrf_token"')

    def test_main_serves_static_and_disables_swagger(self):
        source = (APP / "main.py").read_text(encoding="utf-8")
        self.assertIn('app.mount("/static"', source)
        self.assertIn("docs_url=None", source)
        self.assertIn("redoc_url=None", source)
        self.assertIn("openapi_url=None", source)

    def test_double_award_protection_in_schema_and_code(self):
        models = (APP / "models.py").read_text(encoding="utf-8")
        self.assertIn("UniqueConstraint('user_id', 'challenge_id'", models)
        self.assertIn("primary_key=True", models.split("class Solve")[1])
        self.assertIn("IntegrityError", (APP / "main.py").read_text(encoding="utf-8"))


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

    def test_no_flags_or_hashes_in_pages(self):
        c = self.challenge
        for name, ctx in {"challenges.html": dict(challenges=[c], solved_ids=set()),
                          "admin.html": dict(challenges=[c], attempts=[])}.items():
            html = self.render(name, user="admin", **ctx)
            self.assertNotIn("CTF{", html.replace('placeholder="CTF{...}"', ""))


class InitTests(unittest.TestCase):
    SECRET = "x" * 40

    def test_hash_formula_equals_backend(self):
        """Берём настоящую hash_flag() из main.py и сравниваем с формулой инициализации."""
        fn = next(n for n in MAIN_TREE.body if isinstance(n, ast.FunctionDef) and n.name == "hash_flag")
        ns = {"hashlib": hashlib, "hmac": hmac, "SECRET_KEY": self.SECRET}
        exec(compile(ast.Module([fn], []), "main.py", "exec"), ns)
        for flag in ("CTF{abc}", "CTF{идор}", tf.DEFAULT_FLAGS["WEB01_FLAG"]):
            self.assertEqual(ns["hash_flag"](flag), tf.hash_flag(self.SECRET, flag))

    def test_seed_columns_exist_in_backend_model(self):
        cls = next(n for n in MODELS_TREE.body if isinstance(n, ast.ClassDef) and n.name == "Challenge")
        model_columns = {n.target.id for n in cls.body if isinstance(n, ast.AnnAssign)}
        used = {"title", "category", "difficulty", "description", "points", "flag_hash", "is_published", "resource_url"}
        self.assertLessEqual(used, model_columns)
        self.assertIn("Challenge(", (APP / "init_db.py").read_text(encoding="utf-8"))

    def test_seed_values_accepted_by_backend_validation(self):
        codes = set()
        for item in tf.CHALLENGES:
            self.assertIn(item["category"], ("Web", "Crypto"))
            self.assertIn(item["difficulty"], ("easy", "medium", "hard"))
            self.assertTrue(1 <= item["points"] <= 1000)
            self.assertLessEqual(len(item["title"]), 140)
            self.assertTrue(item["title"].startswith(item["code"]))
            self.assertTrue(item["resource_url"].startswith("/"))
            codes.add(item["code"])
        self.assertEqual(codes, {"WEB-01", "WEB-02", "CRYPTO-01"})
        self.assertEqual(sorted(i["points"] for i in tf.CHALLENGES), [100, 150, 150])
        main_source = (APP / "main.py").read_text(encoding="utf-8")
        self.assertIn('category not in ("Web", "Crypto")', main_source)

    def test_secret_key_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(tf.ConfigError, "SECRET_KEY"):
                init_db.resolve_secret_key({"SECRET_KEY": "short"}, tmp)
            self.assertEqual(init_db.resolve_secret_key({"SECRET_KEY": self.SECRET}, tmp), (self.SECRET, "env"))
            first, source1 = init_db.resolve_secret_key({}, tmp)
            second, source2 = init_db.resolve_secret_key({"SECRET_KEY": ""}, tmp)
            self.assertEqual((source1, source2), ("generated", "file"))
            self.assertEqual(first, second)                    # ключ переживает перезапуск
            self.assertGreaterEqual(len(first), 32)
            if os.name == "posix":
                self.assertEqual((Path(tmp) / "secret_key").stat().st_mode & 0o777, 0o600)

    def test_admin_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "t.db")
            with self.assertRaisesRegex(tf.ConfigError, "ADMIN_PASSWORD"):
                init_db.resolve_admin({"ADMIN_PASSWORD": "short"}, db)
            user, password, show, new = init_db.resolve_admin({}, db)       # первый запуск без пароля
            self.assertEqual((user, show, new), ("teacher", True, True))
            self.assertGreaterEqual(len(password), 12)
            self.assertEqual(init_db.resolve_admin({"ADMIN_PASSWORD": "a" * 12}, db)[1:], ("a" * 12, False, True))
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
            con.execute("INSERT INTO users (username) VALUES ('teacher')")
            con.commit(); con.close()
            user, password, show, new = init_db.resolve_admin({}, db)       # перезапуск: пароль не показываем
            self.assertEqual((show, new), (False, False))
            self.assertGreaterEqual(len(password), 12)                      # main.py всё равно требует 12+

    def test_sqlite_path(self):
        self.assertEqual(init_db.sqlite_path("sqlite:////data/cyberarena.db"), "/data/cyberarena.db")
        self.assertEqual(init_db.sqlite_path("sqlite:///./cyberarena.db"), "./cyberarena.db")
        with self.assertRaises(tf.ConfigError):
            init_db.sqlite_path("postgresql://x")

    def test_init_starts_uvicorn_and_hides_flags_from_web_process(self):
        source = (APP / "init_db.py").read_text(encoding="utf-8")
        self.assertIn("os.execv", source)
        self.assertIn('"main:app"', source)
        self.assertIn("os.environ.pop(name, None)", source)
        dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(dockerfile, r'CMD \["python", "init_db\.py"\]')
        self.assertIn("USER app", dockerfile)


try:
    import sqlalchemy  # noqa: F401
    HAVE_SQLALCHEMY = True
except ImportError:      # pragma: no cover
    HAVE_SQLALCHEMY = False


@unittest.skipUnless(HAVE_SQLALCHEMY, "SQLAlchemy не установлен (pip install -r app/requirements.txt)")
class SeedDatabaseTests(unittest.TestCase):
    SECRET = "x" * 40

    def engine(self, tmp):
        from sqlalchemy import create_engine
        return create_engine("sqlite:///%s/t.sqlite" % tmp)

    def rows(self, engine):
        from sqlalchemy import select
        from sqlalchemy.orm import Session
        from models import Challenge
        with Session(engine) as db:
            return db.scalars(select(Challenge).order_by(Challenge.id)).all()

    def test_empty_database_gets_three_published_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self.engine(tmp)
            self.assertEqual(init_db.seed_database(engine, self.SECRET, tf.DEFAULT_FLAGS), (3, 0))
            rows = self.rows(engine)
            self.assertEqual([r.title.split()[0] for r in rows], ["WEB-01", "WEB-02", "CRYPTO-01"])
            self.assertTrue(all(r.is_published for r in rows))
            self.assertEqual(rows[0].flag_hash, tf.hash_flag(self.SECRET, tf.DEFAULT_FLAGS["WEB01_FLAG"]))
            self.assertNotIn("CTF{", " ".join(r.flag_hash + r.description for r in rows))
            engine.dispose()

    def test_second_start_changes_nothing_and_flag_change_is_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self.engine(tmp)
            init_db.seed_database(engine, self.SECRET, tf.DEFAULT_FLAGS)
            self.assertEqual(init_db.seed_database(engine, self.SECRET, tf.DEFAULT_FLAGS), (0, 0))
            self.assertEqual(len(self.rows(engine)), 3)
            changed = dict(tf.DEFAULT_FLAGS, WEB01_FLAG="CTF{new_tournament_flag}")
            self.assertEqual(init_db.seed_database(engine, self.SECRET, changed), (0, 1))
            self.assertEqual(self.rows(engine)[0].flag_hash, tf.hash_flag(self.SECRET, "CTF{new_tournament_flag}"))
            engine.dispose()

    def test_renamed_task_is_not_recreated(self):
        from sqlalchemy.orm import Session
        with tempfile.TemporaryDirectory() as tmp:
            engine = self.engine(tmp)
            init_db.seed_database(engine, self.SECRET, tf.DEFAULT_FLAGS)
            with Session(engine) as db:
                row = self.rows(engine)[1]
                db.get(type(row), row.id).title = "Моё задание"
                db.commit()
            self.assertEqual(init_db.seed_database(engine, self.SECRET, tf.DEFAULT_FLAGS), (0, 0))
            self.assertEqual(len(self.rows(engine)), 3)       # дубликат WEB-02 не создан
            engine.dispose()


class ConfigTests(unittest.TestCase):
    def test_compose_is_zero_config_and_lab_is_isolated(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml не установлен")
        compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
        app, lab, nginx = (compose["services"][n] for n in ("app", "lab-web", "nginx"))
        self.assertNotIn("env_file", app)
        for line in app["environment"].values():
            self.assertNotRegex(str(line), r"\$\{[A-Z0-9_]+:\?")        # ни одной обязательной переменной
        self.assertEqual(list(lab["environment"]), ["WEB01_FLAG"])        # лаборатория знает только свой флаг
        self.assertIs(lab["read_only"], True)
        self.assertEqual(lab["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", lab["security_opt"])
        self.assertEqual(lab["mem_limit"], "256m")
        self.assertEqual(lab["networks"], ["lab-net"])
        self.assertIs(compose["networks"]["lab-net"]["internal"], True)
        self.assertNotIn("volumes", lab)                                  # нет доступа к тому с базой
        for key in ("privileged", "network_mode", "ports"):
            self.assertNotIn(key, lab)
        self.assertEqual(nginx["ports"], ["127.0.0.1:8080:80"])
        for service in (app, lab, nginx):
            self.assertIn("healthcheck", service)

    def test_nginx_proxies_lab_with_503_page_and_limits(self):
        conf = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
        self.assertEqual(conf.count("{"), conf.count("}"))
        for needle in ("location /lab/", "error_page 502 503 504 = @lab_down", "return 503",
                       "limit_req_zone", "limit_req_status 429", "POST:/(login|register)", "/challenges/[0-9]+/submit"):
            self.assertIn(needle, conf)
        self.assertNotIn("alias /usr/share/nginx/static", conf)

    def test_env_example_is_fully_optional(self):
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            self.assertTrue(not line.strip() or line.lstrip().startswith("#"), "активная строка в .env.example: %r" % line)

    def test_text_files_use_lf_and_gitattributes_forces_it(self):
        """Git на Windows подставляет CRLF и ломает конфиги: нужны LF и .gitattributes."""
        for path in (ROOT / "nginx" / "nginx.conf", ROOT / "compose.yaml", APP / "Dockerfile", APP / "init_db.py"):
            self.assertNotIn(b"\r\n", path.read_bytes(), "%s содержит CRLF" % path.name)
        attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("*.py text eol=lf", attrs)
        self.assertIn("*.conf text eol=lf", attrs)


if __name__ == "__main__":
    unittest.main()
