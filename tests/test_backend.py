import importlib, re, sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.sqlite")
    monkeypatch.setenv("SECRET_KEY", "secure-test-key-at-least-32-characters-long")
    monkeypatch.setenv("ADMIN_USERNAME", "teacher")
    monkeypatch.setenv("ADMIN_PASSWORD", "teacher-test-password")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
    for name in ("main", "models"):
        sys.modules.pop(name, None)
    module = importlib.import_module("main")
    with TestClient(module.app) as client:
        yield client, module
    sys.path.pop(0)

def token(client, url):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(url).text).group(1)

def test_core_flow(client):
    c, app = client
    assert c.get("/health").status_code == 200
    assert c.post("/register", data={"username":"alice","password":"strong-player-password","csrf_token":token(c,"/register")}, follow_redirects=False).status_code == 303
    assert c.get("/admin").status_code == 403
    c.post("/logout", data={"csrf_token":token(c, "/")})
    c.post("/login", data={"username":"teacher","password":"teacher-test-password","csrf_token":token(c,"/login")})
    assert c.get("/admin").status_code == 403
    assert c.post("/change-password", data={"old_password":"teacher-test-password","new_password":"changed-teacher-password","csrf_token":token(c,"/change-password")}, follow_redirects=False).status_code == 303
    assert c.post("/admin/challenges", data={"title":"Demo","category":"Web","description":"Find the flag","points":100,"flag":"CTF{testing}","csrf_token":token(c,"/admin")}, follow_redirects=False).status_code == 303
    assert c.post("/admin/challenges/1/edit", data={"title":"Demo","category":"Web","description":"Find the flag","points":100,"is_published":"true","csrf_token":token(c,"/admin")}, follow_redirects=False).status_code == 303
    c.post("/logout", data={"csrf_token":token(c,"/")})
    c.post("/login", data={"username":"alice","password":"strong-player-password","csrf_token":token(c,"/login")})
    csrf = token(c,"/challenges/1")
    assert c.post("/challenges/1/submit", data={"flag":"CTF{testing}","csrf_token":csrf}, follow_redirects=False).status_code == 303
    with app.SessionLocal.begin() as db:
        assert db.query(app.Solve).count() == 1
        entry = db.query(app.Submission).first()
        entry.submitted_at -= app.timedelta(seconds=4)
    c.post("/challenges/1/submit", data={"flag":"CTF{testing}","csrf_token":csrf}, follow_redirects=False)
    with app.SessionLocal() as db:
        assert db.query(app.Solve).count() == 1
    assert "100" in c.get("/leaderboard").text


def register(c, username):
    return c.post("/register", data={"username": username, "password": "fixture-password-123",
                                    "csrf_token": token(c, "/register")}, follow_redirects=False)


def login(c, username, password="fixture-password-123"):
    return c.post("/login", data={"username": username, "password": password,
                                 "csrf_token": token(c, "/login")}, follow_redirects=False)


def add_challenge(app, points=100):
    with app.SessionLocal.begin() as db:
        item = app.Challenge(title="Test card", category="Web", difficulty="easy",
                             description="Complete the exercise", points=points,
                             flag_hash=app.hash_flag("CTF{fixture_correct}"), is_published=True)
        db.add(item)
        db.flush()
        return item.id


def test_parallel_submissions_respect_cooldown_and_award_once(client):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    c, app = client
    challenge_id = add_challenge(app)
    assert register(c, "parallel_player").status_code == 303
    path = f"/challenges/{challenge_id}"
    fields = {"flag": "CTF{fixture_correct}", "csrf_token": token(c, path)}
    barrier = Barrier(2)

    def submit():
        barrier.wait(timeout=5)
        return c.post(path + "/submit", data=fields, follow_redirects=False).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        submissions = [pool.submit(submit), pool.submit(submit)]
        assert sorted(future.result(timeout=10) for future in submissions) == [303, 429]
    with app.SessionLocal.begin() as db:
        assert db.query(app.Solve).count() == 1
        assert db.query(app.Submission).count() == 1
        db.query(app.Submission).one().submitted_at -= app.timedelta(seconds=4)
    assert c.post(path + "/submit", data=fields, follow_redirects=False).status_code == 303
    with app.SessionLocal() as db:
        assert db.query(app.Solve).count() == 1
        assert db.query(app.Submission).count() == 2


def test_logout_revokes_server_session_and_checks_csrf(client):
    c, app = client
    assert register(c, "logout_player").status_code == 303
    csrf = token(c, "/profile")
    assert c.post("/logout", data={"csrf_token": "неверный"}).status_code == 403
    assert c.get("/profile").status_code == 200
    assert c.post("/logout", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
    assert c.get("/profile").status_code == 401
    with app.SessionLocal() as db:
        assert db.query(app.LoginSession).count() == 0


def test_password_change_revokes_other_browser_and_expiry_is_server_checked(client):
    c, app = client
    assert register(c, "password_player").status_code == 303
    with TestClient(app.app) as second:
        assert login(second, "password_player").status_code == 303
        assert second.get("/profile").status_code == 200
        updated = "another-fixture-password"
        response = c.post("/change-password", data={
            "old_password": "fixture-password-123", "new_password": updated,
            "csrf_token": token(c, "/change-password"),
        }, follow_redirects=False)
        assert response.status_code == 303
        assert second.get("/profile").status_code == 401
        assert c.get("/profile").status_code == 200
        assert login(second, "password_player").status_code == 401
        assert login(second, "password_player", updated).status_code == 303
        with app.SessionLocal.begin() as db:
            for session in db.query(app.LoginSession):
                session.expires_at = app.utcnow() - app.timedelta(seconds=1)
        assert second.get("/profile").status_code == 401
        assert c.get("/profile").status_code == 401


def test_html_errors_keep_safe_fields_and_status(client):
    c, app = client
    assert register(c, "html_player").status_code == 303
    headers = {"Accept": "text/html"}
    response = c.post("/register", headers=headers, data={"username": "html_player",
                      "password": "distinct-fixture-password", "csrf_token": token(c, "/register")})
    assert response.status_code == 409
    assert "Этот логин уже занят" in response.text and 'value="html_player"' in response.text
    assert "distinct-fixture-password" not in response.text
    response = c.post("/login", headers=headers, data={"username": "html_player", "password": "fixture-wrong",
                      "csrf_token": token(c, "/login")})
    assert response.status_code == 401 and "Неверный логин или пароль" in response.text
    assert c.post("/login", data={"username": "html_player"}).status_code == 422
    challenge = add_challenge(app)
    path = f"/challenges/{challenge}"
    response = c.post(path + "/submit", headers=headers,
                      data={"flag": "fixture-secret-invalid", "csrf_token": token(c, path)})
    assert response.status_code == 400 and "Введите флаг" in response.text
    assert "fixture-secret-invalid" not in response.text


def test_admin_posts_are_denied_and_tied_scores_order_by_last_solve(client):
    from sqlalchemy import select

    c, app = client
    challenge = add_challenge(app)
    assert register(c, "z_earlier_player").status_code == 303
    assert register(c, "a_later_player").status_code == 303
    csrf = token(c, "/profile")
    fields = {"csrf_token": csrf, "title": "New title", "description": "Exercise",
              "points": "100", "category": "Web", "flag": "CTF{fixture_admin_flag}"}
    for route in ("/admin/challenges", f"/admin/challenges/{challenge}/edit"):
        assert c.post(route, data=fields).status_code == 403
    assert c.post("/admin/reset", data={"confirmation": "RESET", "csrf_token": csrf}).status_code == 403
    with app.SessionLocal.begin() as db:
        for index, username in enumerate(("z_earlier_player", "a_later_player")):
            user_id = db.scalar(select(app.User.id).where(app.User.username == username))
            db.add(app.Solve(user_id=user_id, challenge_id=challenge,
                             solved_at=app.utcnow() + app.timedelta(seconds=index)))
    text = c.get("/leaderboard").text.split("leader-panel", 1)[1]
    assert text.index("z_earlier_player") < text.index("a_later_player")


def test_login_handles_quoted_input_and_errors_escape_user_fields(client):
    c, _ = client
    assert register(c, "plain_player").status_code == 303
    response = login(c, "O'Brief")
    assert response.status_code == 401
    c.get("/login")
    response = c.post("/login", headers={"Accept": "text/html"}, data={
        "username": 'Examples: "quotes" & <labels>', "password": "fictional-password",
        "csrf_token": token(c, "/login"),
    })
    assert response.status_code == 401
    assert "&lt;labels&gt;" in response.text and "<labels>" not in response.text


def test_demo_reset_is_disabled_for_tournament_admin(client):
    c, app = client
    assert login(c, "teacher", "teacher-test-password").status_code == 303
    assert c.post("/change-password", data={"old_password": "teacher-test-password",
                  "new_password": "updated-teacher-fixture",
                  "csrf_token": token(c, "/change-password")}, follow_redirects=False).status_code == 303
    assert 'action="/admin/reset"' not in c.get("/admin").text
    assert c.post("/admin/reset", data={"confirmation": "RESET", "csrf_token": token(c, "/admin")}).status_code == 403


def test_builtin_material_is_managed_at_deployment_and_custom_hash_survives_init(client):
    import init_db
    import task_files

    c, app = client
    flags = task_files.load_flags({})
    init_db.seed_database(app.engine, app.SECRET_KEY, flags)
    assert login(c, "teacher", "teacher-test-password").status_code == 303
    assert c.post("/change-password", data={"old_password": "teacher-test-password",
                  "new_password": "updated-teacher-fixture",
                  "csrf_token": token(c, "/change-password")}, follow_redirects=False).status_code == 303
    form = {"csrf_token": token(c, "/admin"), "title": "Renamed card", "category": "Web",
            "description": "Fixture description", "points": "100", "is_published": "true",
            "resource_url": "/lab/"}
    builtin = c.post("/admin/challenges/1/edit", data=dict(form, flag="CTF{unmatched_resource}"))
    assert builtin.status_code == 400
    assert c.post("/admin/challenges/1/edit", data=form, follow_redirects=False).status_code == 303
    custom_id = add_challenge(app)
    edit = c.post(f"/admin/challenges/{custom_id}/edit",
                  data=dict(form, flag="CTF{updated_custom_flag}"), follow_redirects=False)
    assert edit.status_code == 303
    assert init_db.seed_database(app.engine, app.SECRET_KEY, flags) == (0, 0)
    with app.SessionLocal() as db:
        assert db.get(app.Challenge, 1).title == "Renamed card"
        assert db.get(app.Challenge, custom_id).flag_hash == app.hash_flag("CTF{updated_custom_flag}")


def test_demo_reset_removes_results_but_preserves_accounts_and_cards(client, monkeypatch):
    c, app = client
    monkeypatch.setattr(app, "DEMO_RESET", True)
    challenge_id = add_challenge(app)
    assert register(c, "demo_participant").status_code == 303
    path = f"/challenges/{challenge_id}"
    response = c.post(path + "/submit", data={
        "flag": "CTF{fixture_correct}", "csrf_token": token(c, path),
    }, follow_redirects=False)
    assert response.status_code == 303

    assert login(c, "teacher", "teacher-test-password").status_code == 303
    response = c.post("/change-password", data={
        "old_password": "teacher-test-password", "new_password": "updated-teacher-fixture",
        "csrf_token": token(c, "/change-password"),
    }, follow_redirects=False)
    assert response.status_code == 303
    csrf = token(c, "/admin")
    assert c.post("/admin/reset", data={"confirmation": "RESET", "csrf_token": "invalid"}).status_code == 403
    assert c.post("/admin/reset", data={"confirmation": "cancel", "csrf_token": csrf}).status_code == 400
    with app.SessionLocal() as db:
        assert db.query(app.Solve).count() == db.query(app.Submission).count() == 1
    assert c.post("/admin/reset", data={"confirmation": "RESET", "csrf_token": csrf},
                  follow_redirects=False).status_code == 303
    with app.SessionLocal() as db:
        assert db.query(app.Solve).count() == db.query(app.Submission).count() == 0
        assert db.query(app.User).count() == 2
        assert db.query(app.Challenge).count() == 1


def test_teacher_challenge_crud_preserves_history(client):
    c, app = client
    assert login(c, "teacher", "teacher-test-password").status_code == 303
    assert c.post("/change-password", data={
        "old_password": "teacher-test-password", "new_password": "changed-teacher-password",
        "csrf_token": token(c, "/change-password"),
    }, follow_redirects=False).status_code == 303
    csrf = token(c, "/admin")
    fields = {
        "title": "CRUD draft", "category": "Crypto", "description": "Demo card",
        "points": 117, "flag": "CTF{fixture_crud}", "csrf_token": csrf,
    }
    assert c.post("/admin/challenges", data=fields, follow_redirects=False).status_code == 303
    with app.SessionLocal() as db:
        card_id = db.query(app.Challenge).filter_by(title="CRUD draft").one().id
    assert "CRUD draft" in c.get("/admin").text
    path = f"/admin/challenges/{card_id}"
    assert c.post(path + "/edit", data=dict(fields, title="CRUD edited", is_published="true"),
                  follow_redirects=False).status_code == 303
    assert "CRUD edited" in c.get("/admin").text
    deletion = {"confirmation": "DELETE", "csrf_token": csrf}
    assert c.post(path + "/delete", data=deletion).status_code == 409
    assert c.post(path + "/edit", data=dict(fields, title="CRUD edited"),
                  follow_redirects=False).status_code == 303
    assert path + "/delete" in c.get("/admin").text
    assert c.post(path + "/delete", data=dict(deletion, csrf_token="invalid")).status_code == 403
    assert c.post(path + "/delete", data=dict(deletion, confirmation="cancel")).status_code == 400
    assert c.post(path + "/delete", data=deletion, follow_redirects=False).status_code == 303
    assert "CRUD edited" not in c.get("/admin").text
    assert c.post(path + "/delete", data=deletion).status_code == 404

    solved_id = add_challenge(app, points=137)
    attempts_id = add_challenge(app)
    with TestClient(app.app) as player:
        assert register(player, "crud_participant").status_code == 303
        for challenge_id, flag in ((solved_id, "CTF{fixture_correct}"), (attempts_id, "CTF{wrong}")):
            card_path = f"/challenges/{challenge_id}"
            player_csrf = token(player, card_path)
            assert player.post(f"/admin/challenges/{challenge_id}/delete",
                               data=dict(deletion, csrf_token=player_csrf)).status_code == 403
            assert player.post(card_path + "/submit", data={"flag": flag, "csrf_token": player_csrf},
                               follow_redirects=False).status_code == 303
        for challenge_id in (solved_id, attempts_id):
            challenge_path = f"/admin/challenges/{challenge_id}"
            with app.SessionLocal() as db:
                points = db.get(app.Challenge, challenge_id).points
            assert c.post(challenge_path + "/edit", data=dict(fields, flag="", points=points),
                          follow_redirects=False).status_code == 303
            assert c.post(challenge_path + "/delete", data=deletion).status_code == 409
        assert f'href="/challenges/{solved_id}"' not in player.get("/challenges").text
        assert re.search(r">\s*137\s*<", player.get("/leaderboard").text)
    with app.SessionLocal() as db:
        assert db.query(app.Solve).count() == 1
        assert db.query(app.Submission).count() == 2
        assert db.get(app.Challenge, solved_id) is not None
        assert db.get(app.Challenge, attempts_id) is not None
