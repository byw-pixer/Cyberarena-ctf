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
