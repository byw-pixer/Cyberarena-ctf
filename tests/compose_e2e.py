"""Functional acceptance with disposable users on a new local Compose project."""
import argparse
import base64
import json
import os
import re
import secrets
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from urllib.parse import unquote_plus

import httpx

ROOT = Path(__file__).resolve().parent.parent


def main():
    if not __debug__:
        raise SystemExit("Run this acceptance test without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--firefox-bidi", type=int, help="Local Firefox WebDriver BiDi port")
    args = parser.parse_args()
    if not args.project.startswith("cyberarena-test-") or not 1024 < args.port < 65536 or args.port == 8080:
        parser.error("Use a new cyberarena-test-* project and a separate loopback port")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", args.port))
        except OSError as exc:
            parser.error(f"Loopback port {args.port} is unavailable: {exc.strerror}")
    flags = {name: "CTF{" + secrets.token_hex(16) + "}" for name in
             ("WEB01_FLAG", "WEB02_FLAG", "CRYPTO01_FLAG")}
    password = secrets.token_urlsafe(20)
    changed_password = secrets.token_urlsafe(20)
    env = dict(os.environ, **flags, FLAG_REVISION="", ADMIN_USERNAME="acceptance_teacher",
               ADMIN_PASSWORD=password, CYBERARENA_PORT=str(args.port))
    # The test does not inherit the production .env or signing key.
    env.update(SECRET_KEY="", DEMO_RESET="false")
    command = ["docker", "compose", "--env-file", os.devnull, "-f", str(ROOT / "compose.yaml"),
               "-p", args.project]

    def compose(*arguments, input_text=None):
        return subprocess.run(command + list(arguments), cwd=ROOT, env=env, capture_output=True,
                              text=True, input=input_text, check=True, timeout=180).stdout.strip()

    if compose("ps", "-a", "-q"):
        parser.error("The selected project already has containers")
    existing = subprocess.run(["docker", "volume", "ls", "-q", "--filter",
                               f"label=com.docker.compose.project={args.project}"], env=env, text=True,
                              capture_output=True, check=True, timeout=20)
    if existing.stdout.strip():
        parser.error("The selected project already has volumes")
    compose("up", "-d", "--build", "--wait", "--wait-timeout", "75")
    services = [
        json.loads(line) for line in compose("ps", "--format", "json").splitlines()
    ]
    assert {service["Service"]: service["Health"] for service in services} == {
        "nginx": "healthy", "app": "healthy", "lab-web": "healthy",
    }
    print("PASS clean Compose build and three healthy services", flush=True)
    fixture_matches = compose("exec", "-T", "lab-web", "python", "-c", """
from hmac import compare_digest
from sys import stdin
from app import get_flag
assert compare_digest(get_flag(), stdin.read())
print("ok")
""", input_text=flags["WEB01_FLAG"])
    assert fixture_matches == "ok"
    print("PASS WEB-01 lab material matches the synthetic acceptance fixture", flush=True)
    base = f"http://127.0.0.1:{args.port}"
    clients = []

    def browser():
        c = httpx.Client(base_url=base, trust_env=False, timeout=30,
                         headers={"Accept": "text/html"})
        clients.append(c)
        return c

    def check(response, status):
        if response.status_code != status:
            raise AssertionError((response.request.url.path, response.status_code, status))
        return response

    def csrf(c, path):
        return re.search(r'name="csrf_token" value="([^"]+)"', check(c.get(path), 200).text)[1]

    def post(c, path, source, **values):
        return c.post(path, data=dict(values, csrf_token=csrf(c, source)))

    def submit(c, card, flag):
        return post(c, f"/challenges/{card}/submit", f"/challenges/{card}", flag=flag)

    def certify_snapshot():
        snapshot = compose("exec", "-T", "app", "python", "backup.py")
        healthy = compose("exec", "-T", "app", "python", "-c", """
import sqlite3, sys
from pathlib import Path
path = Path(sys.argv[1])
db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
assert not db.execute('PRAGMA foreign_key_check').fetchall()
assert path.stat().st_mode & 0o077 == 0
print('ok')
""", snapshot)
        assert healthy == "ok"

    certify_snapshot()
    print("PASS private SQLite backup with integrity_check and foreign_key_check", flush=True)

    def account(name):
        c = browser()
        check(post(c, "/register", "/register", username=name, password=password), 303)
        check(post(c, "/logout", "/profile"), 303)
        check(post(c, "/login", "/login", username=name, password=password), 303)
        catalog = check(c.get("/challenges"), 200).text
        assert all(f'href="/challenges/{card}"' in catalog for card in range(1, 4))
        return c

    alice, bob = account("qa_alice"), account("qa_bob")
    redirect = check(alice.get("/lab"), 301)
    assert redirect.headers["location"] == "/lab/"
    lab = check(alice.get("/lab/"), 200)
    assert "Школьный портал" in lab.text
    assert "sandbox" in lab.headers["Content-Security-Policy"]
    assert "Set-Cookie" not in lab.headers
    assert not check(alice.head("/lab/"), 200).content
    vault = check(alice.get("/static/tasks/web02/vault.js"), 200).text
    parts = json.loads(re.search(r"var parts = (\[.*?\]);", vault)[1])
    web02 = "".join(base64.b64decode(part).decode() for part in parts)
    cipher = check(alice.get("/static/tasks/crypto01/cipher.txt"), 200).text
    key = "cyberarena"
    output = []
    index = 0
    for char in cipher:
        if char.isascii() and char.isalpha():
            offset = ord("A" if char.isupper() else "a")
            output.append(chr(offset + (ord(char) - offset - (ord(key[index % len(key)]) - 97)) % 26))
            index += 1
        else:
            output.append(char)
    crypto01 = re.search(r"CTF\{[^}]+\}", "".join(output))[0]
    assert web02 == flags["WEB02_FLAG"] and crypto01 == flags["CRYPTO01_FLAG"]
    assert web02 not in vault and crypto01 not in cipher
    # WEB-01 is seeded with a synthetic fixture here. This checks the verifier
    # independently of the intentionally vulnerable lab exercise.
    solved = (flags["WEB01_FLAG"], web02, crypto01)
    for card, flag in enumerate(solved, 1):
        wrong = check(submit(alice, card, "CTF{invalid_fixture}"), 303)
        assert "Неверный флаг" in unquote_plus(wrong.headers["location"])
        assert flag not in check(alice.get(f"/challenges/{card}"), 200).text
    time.sleep(3.1)
    for card, flag in enumerate(solved, 1):
        response = check(submit(alice, card, flag), 303)
        assert "Верно" in unquote_plus(response.headers["location"])
    print("PASS two independent accounts; all three reject wrong and accept correct flags; two live resources decoded", flush=True)
    nonce = csrf(bob, "/challenges/1")
    barrier = Barrier(2)

    def parallel():
        barrier.wait(timeout=10)
        return bob.post("/challenges/1/submit", data={"flag": solved[0], "csrf_token": nonce}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(parallel) for _ in range(2)]
        assert sorted(future.result() for future in futures) == [303, 429]

    def active_player(index):
        c = account(f"qa_load_{index:02}")
        check(submit(c, 1, solved[0]), 303)
        check(c.get("/leaderboard"), 200)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(active_player, range(6)))
    print(f"PASS 6 concurrent players, {time.monotonic() - started:.2f}s; parallel same-user submission 303/429", flush=True)
    check(submit(alice, 1, solved[0]), 303)
    instructor = browser()
    initial_login = check(post(instructor, "/login", "/login", username="acceptance_teacher", password=password), 303)
    assert initial_login.headers["location"] == "/change-password"
    assert check(instructor.get("/admin"), 303).headers["location"] == "/change-password"
    check(post(instructor, "/change-password", "/change-password",
               old_password=password, new_password=changed_password), 303)
    card = {"category": "Web", "difficulty": "easy", "description": "QA draft",
            "points": "73", "title": "QA hidden", "flag": "CTF{isolated_qa_card}"}
    check(post(alice, "/admin/challenges", "/profile", **card), 403)
    check(post(instructor, "/admin/challenges", "/admin", **card), 303)
    check(alice.get("/challenges/4"), 404)
    card["title"] = "QA published"
    check(post(instructor, "/admin/challenges/4/edit", "/admin", **card, is_published="true"), 303)
    assert card["title"] in check(alice.get("/challenges/4"), 200).text
    check(post(instructor, "/admin/challenges/4/edit", "/admin", **card, is_published="false"), 303)
    check(alice.get("/challenges/4"), 404)
    check(post(instructor, "/admin/challenges/4/edit", "/admin", **card, is_published="true"), 303)
    draft = dict(card, title="QA disposable CRUD draft")
    check(post(instructor, "/admin/challenges", "/admin", **draft), 303)
    admin_html = check(instructor.get("/admin"), 200).text
    draft_id = re.search(r"Задание №(\d+) · QA disposable CRUD draft", admin_html)[1]
    delete_path = f"/admin/challenges/{draft_id}/delete"
    assert delete_path in admin_html
    check(post(alice, delete_path, "/profile", confirmation="DELETE"), 403)
    check(post(instructor, delete_path, "/admin", confirmation="cancel"), 400)
    check(post(instructor, delete_path, "/admin", confirmation="DELETE"), 303)
    assert draft["title"] not in check(instructor.get("/admin"), 200).text
    check(post(instructor, delete_path, "/admin", confirmation="DELETE"), 404)
    print("PASS teacher password change and CRUD: create, read, edit, hide, publish, delete", flush=True)
    check(post(instructor, "/admin/challenges/1/edit", "/admin", title="Renamed WEB card", category="Web",
               difficulty="easy", points="100", description="QA built-in edit", resource_url="/lab/",
               is_published="true"), 303)

    def persisted_rows():
        return json.loads(compose("exec", "-T", "app", "python", "-c", """
import json, sqlite3
db = sqlite3.connect('/data/cyberarena.db')
counts = [db.execute('select count(*) from ' + name).fetchone()[0] for name in
          ('users', 'challenges', 'submissions', 'solves')]
print(json.dumps(counts))
"""))

    expected = persisted_rows()
    assert expected == [9, 4, 14, 10], expected
    certify_snapshot()
    compose("restart")
    for _ in range(40):
        try:
            if alice.get("/health").status_code == 200 and alice.get("/lab/health").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(1)
    else:
        raise AssertionError("services did not recover after restart")
    assert persisted_rows() == expected
    leaderboard = check(alice.get("/leaderboard"), 200).text.split("leader-panel", 1)[1]
    assert leaderboard.index("qa_alice") < leaderboard.index("qa_bob") < leaderboard.index("qa_load_")
    assert ">400<" in leaderboard
    assert "Renamed WEB card" in check(alice.get("/challenges/1"), 200).text
    assert card["title"] in check(alice.get("/challenges/4"), 200).text
    check(post(instructor, "/login", "/login", username="acceptance_teacher", password=changed_password), 303)
    admin_html = check(instructor.get("/admin"), 200).text
    solves_html = admin_html.split("Последние 100 решений", 1)[1].split("</table>", 1)[0]
    assert "qa_alice" in solves_html and "Renamed WEB card" in solves_html
    print("PASS Docker restart: 9 users, 4 cards, 14 submissions, 10 solves, 400-point leader and changed admin password", flush=True)

    try:
        compose("stop", "lab-web")
        assert "Лаборатория временно недоступна" in check(alice.get("/lab/"), 503).text
        outage = account("qa_during_outage")
        check(outage.get("/leaderboard"), 200)
    finally:
        compose("start", "--wait", "--wait-timeout", "60", "lab-web")
        for _ in range(30):
            if alice.get("/lab/health").status_code == 200:
                break
            time.sleep(1)
        else:
            raise AssertionError("lab did not recover after outage")
    print("PASS isolated lab stop: registration, login, catalog and rating work; lab recovered", flush=True)
    if args.firefox_bidi:
        subprocess.run(["node", str(ROOT / "tests" / "check_browser.mjs"), str(args.firefox_bidi), base],
                       env=dict(os.environ, BROWSER_TEACHER="acceptance_teacher",
                                BROWSER_TEACHER_PASSWORD=changed_password), check=True, timeout=80)
    for c in clients:
        c.close()


if __name__ == "__main__":
    main()
