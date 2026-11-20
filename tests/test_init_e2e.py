"""Сквозной тест: инициализация -> настоящая платформа -> участник решает три встроенных задания.

Нужны fastapi, sqlalchemy, argon2-cffi и httpx (pip install -r app/requirements.txt pytest httpx),
иначе тест пропускается. Проверяет главное: хеши, созданные init_db.py, принимаются настоящим main.py.
"""
import importlib
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock
import pytest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"

try:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, select
    import argon2  # noqa: F401
    import httpx  # noqa: F401
    HAVE_ALL = True
except ImportError:      # pragma: no cover
    HAVE_ALL = False


def token(client, url):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(url).text).group(1)


@unittest.skipUnless(HAVE_ALL, "не установлены fastapi, sqlalchemy, argon2-cffi, httpx")
class SeededPlatformTests(unittest.TestCase):
    def test_participant_solves_builtin_tasks_and_gets_redirects(self):
        sys.path.insert(0, str(APP))
        try:
            import task_files as tf
            import init_db
            with tempfile.TemporaryDirectory() as tmp:
                url = "sqlite:///%s/t.sqlite" % tmp
                secret = "e2e-secret-key-at-least-32-characters-long"
                env = {"DATABASE_URL": url, "SECRET_KEY": secret, "ADMIN_USERNAME": "teacher",
                       "ADMIN_PASSWORD": "teacher-test-password", "STATIC_DIR": "%s/static" % tmp}
                flags = tf.load_flags({})
                with mock.patch.dict(os.environ, env):
                    engine = create_engine(url, connect_args={"timeout": 20})
                    init_db.seed_database(engine, secret, flags)
                    engine.dispose()
                    tf.prepare_static(APP / "static", "%s/static" % tmp, flags)
                    for name in ("main", "models"):
                        sys.modules.pop(name, None)
                    module = importlib.import_module("main")

                with TestClient(module.app) as c:
                    # статика: стили и файлы заданий отдаёт платформа
                    for path in ("/static/style.css", "/static/tasks/web02/vault.js", "/static/tasks/crypto01/cipher.txt"):
                        self.assertEqual(c.get(path).status_code, 200, path)
                    self.assertNotIn("CTF{", c.get("/static/tasks/crypto01/cipher.txt").text)

                    # гость в браузере попадает на страницу входа, а не видит JSON
                    self.assertEqual(c.get("/challenges").status_code, 401)
                    guest = c.get("/challenges", headers={"accept": "text/html"}, follow_redirects=False)
                    self.assertEqual((guest.status_code, guest.headers["location"]), (303, "/login"))

                    # участник регистрируется и решает все три задания
                    self.assertEqual(c.post("/register", data={"username": "alice", "password": "strong-player-password",
                                     "csrf_token": token(c, "/register")}, follow_redirects=False).status_code, 303)
                    page = c.get("/challenges").text
                    for code in ("WEB-01", "WEB-02", "CRYPTO-01"):
                        self.assertIn(code, page)
                    for challenge_id, name in ((1, "WEB01_FLAG"), (2, "WEB02_FLAG"), (3, "CRYPTO01_FLAG")):
                        response = c.post("/challenges/%d/submit" % challenge_id,
                                          data={"flag": flags[name], "csrf_token": token(c, "/challenges/%d" % challenge_id)},
                                          follow_redirects=False)
                        self.assertEqual(response.status_code, 303, name)
                    with module.SessionLocal() as db:
                        self.assertEqual(db.query(module.Solve).count(), 3)
                    self.assertIn("400", c.get("/leaderboard").text)       # 100 + 150 + 150

                    # общий лимит попыток на пользователя (обход через смену задания невозможен)
                    c.post("/logout", data={"csrf_token": token(c, "/")})
                    c.post("/register", data={"username": "bob", "password": "another-strong-password",
                                              "csrf_token": token(c, "/register")}, follow_redirects=False)
                    with module.SessionLocal.begin() as db:
                        bob = db.scalar(select(module.User.id).where(module.User.username == "bob"))
                        for _ in range(20):
                            db.add(module.Submission(user_id=bob, challenge_id=1, is_correct=False,
                                                     submitted_at=module.utcnow() - timedelta(seconds=30)))
                    limited = c.post("/challenges/2/submit", data={"flag": "CTF{wrong}",
                                     "csrf_token": token(c, "/challenges/2")}, follow_redirects=False)
                    self.assertEqual(limited.status_code, 429)
        finally:
            sys.path.remove(str(APP))
            for name in ("main", "models"):
                sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()


def test_revision_is_explicit_and_preserves_card_edits(tmp_path):
    import task_files as tf
    import init_db
    from models import Challenge
    from sqlalchemy.orm import Session

    engine = create_engine(f"sqlite:///{tmp_path / 'arena.db'}")
    secret = "fixture-secret-used-only-for-regression"
    flags, revision = init_db.resolve_flags({}, tmp_path)
    assert init_db.seed_database(engine, secret, flags, revision) == (3, 0)
    init_db.write_private(tmp_path / "task_flags.json", json.dumps({"revision": revision, "flags": flags}))
    with Session(engine) as db, db.begin():
        card = db.get(Challenge, 2)
        card.title = "Renamed entirely by instructor"
        card.points = 175
    assert init_db.resolve_flags({}, tmp_path) == (flags, revision)
    assert init_db.seed_database(engine, secret, flags, revision) == (0, 0)
    changed = dict(flags, WEB02_FLAG="CTF{fixture_new_round}")
    with pytest.raises(tf.ConfigError):
        init_db.resolve_flags(changed, tmp_path)
    new, revision = init_db.resolve_flags(dict(changed, FLAG_REVISION="round-two"), tmp_path)
    assert init_db.seed_database(engine, secret, new, revision) == (0, 1)
    assert init_db.seed_database(engine, secret, new, revision) == (0, 0)
    with Session(engine) as db:
        card = db.get(Challenge, 2)
        assert (card.title, card.points) == ("Renamed entirely by instructor", 175)
        assert card.flag_hash == tf.hash_flag(secret, changed["WEB02_FLAG"])
    engine.dispose()


def test_legacy_migration_needs_revision_and_retains_solves(tmp_path):
    import task_files as tf
    import init_db
    from models import Base, BuiltinChallenge, Challenge, Solve, User
    from sqlalchemy.orm import Session

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    secret = "fixture-legacy-secret"
    old = tf.load_flags({})
    new = tf.load_flags({})
    Base.metadata.create_all(engine)
    with Session(engine) as db, db.begin():
        for index, item in enumerate(tf.CHALLENGES, 1):
            db.add(Challenge(id=index, title=item["title"], category=item["category"],
                             description=item["description"], points=item["points"],
                             flag_hash=tf.hash_flag(secret, old[item["flag_env"]]),
                             is_published=True, resource_url=item["resource_url"]))
        db.add(User(id=1, username="legacy_player", password_hash="unused-test-hash"))
        db.add(Solve(user_id=1, challenge_id=1))
    with pytest.raises(tf.ConfigError):
        init_db.seed_database(engine, secret, new)
    with Session(engine) as db:
        assert db.get(Challenge, 1).flag_hash == tf.hash_flag(secret, old["WEB01_FLAG"])
        assert db.get(BuiltinChallenge, "WEB-01") is None
    assert init_db.seed_database(engine, secret, new, "migrate-once") == (0, 3)
    with Session(engine) as db:
        assert db.get(BuiltinChallenge, "WEB-01").challenge_id == 1
        assert db.get(Solve, (1, 1))
        assert db.get(User, 1).username == "legacy_player"
    engine.dispose()
