import hashlib, hmac, logging, os, re, secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import urlencode, urlsplit
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, delete, event, func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from models import Base, BuiltinChallenge, Challenge, LoginSession, Solve, Submission, User, utcnow

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberarena.db")
SECRET_KEY = os.getenv("SECRET_KEY", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_BOOTSTRAP_FILE = os.getenv("ADMIN_BOOTSTRAP_FILE")
DEMO_RESET = os.getenv("DEMO_RESET") == "true" and os.getenv("DEPLOYMENT_NAME", "").startswith("cyberarena-demo-")
STATIC_DIR = os.getenv("STATIC_DIR", "/tmp/cyberarena-static")   # заполняется init_db.py
if len(SECRET_KEY) < 32 or not ADMIN_USERNAME or len(ADMIN_PASSWORD) < 12:
    raise RuntimeError("Configure SECRET_KEY (32+), ADMIN_USERNAME and ADMIN_PASSWORD (12+) in .env")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 20} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def setup_sqlite(conn, record):
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=20000")
        conn.execute("PRAGMA journal_mode=WAL")
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
hasher = PasswordHasher()
# Default Argon2id uses 64 MiB per operation. Bound parallel work under the container RAM limit.
password_slots = BoundedSemaphore(4)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def hash_password(password):
    with password_slots:
        return hasher.hash(password)


def verify_password(password_hash, password):
    with password_slots:
        try:
            return hasher.verify(password_hash, password)
        except VerificationError:
            return False


def hash_flag(flag):
    return hmac.new(SECRET_KEY.encode(), flag.encode(), hashlib.sha256).hexdigest()

@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with SessionLocal.begin() as db:
        admin = db.scalar(select(User).where(User.username == ADMIN_USERNAME))
        if admin is None:
            db.add(User(username=ADMIN_USERNAME, password_hash=hash_password(ADMIN_PASSWORD), is_admin=True, must_change_password=True))
        elif not admin.is_admin:
            raise RuntimeError("Admin username already taken by player")
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
SESSION_AGE = timedelta(hours=8)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="strict", max_age=int(SESSION_AGE.total_seconds()))
# Стили и файлы заданий WEB-02 и CRYPTO-01. check_dir=False: каталог создаёт init_db.py, а не импорт модуля.
app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")

def get_db():
    with SessionLocal() as db:
        yield db

def csrf(request):
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]

def validate_csrf(request, token):
    if not request.session.get("csrf") or not hmac.compare_digest(request.session["csrf"].encode(), token.encode()):
        raise HTTPException(403, "Invalid CSRF token")

def session_hash(request):
    token = request.session.get("sid")
    return hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) else None


def user_for(request, db):
    digest = session_hash(request)
    active = db.get(LoginSession, digest) if digest else None
    return db.get(User, active.user_id) if active and active.expires_at > utcnow() else None


def issue_session(db, user_id):
    now = utcnow()
    db.execute(delete(LoginSession).where(LoginSession.expires_at <= now))
    token = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                        user_id=user_id, expires_at=now + SESSION_AGE))
    return token


def set_session(request, token):
    request.session.clear()
    request.session["sid"] = token


def begin_write(db):
    # Serialize SQLite's read/check/write sequence across workers before any reads.
    try:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    except OperationalError as exc:
        if (getattr(exc.orig, "sqlite_errorcode", 0) & 255) in (5, 6):
            raise HTTPException(503, "Database busy, try again", headers={"Retry-After": "1"}) from exc
        raise


def require_user(request, db):
    user = user_for(request, db)
    if not user:
        raise HTTPException(401, "Login required")
    if user.must_change_password and request.url.path not in ("/change-password", "/logout"):
        raise HTTPException(403, "Please change initial password")
    return user

def require_admin(request, db):
    user = require_user(request, db)
    if not user.is_admin:
        raise HTTPException(403, "Admin only")
    return user

def page(request, filename, db, status_code=200, headers=None, **kwargs):
    return templates.TemplateResponse(
        request, filename, {"user": user_for(request, db), "csrf": csrf(request), **kwargs},
        status_code=status_code, headers={"Cache-Control": "no-store", **(headers or {})},
    )

def redirect(path):
    return RedirectResponse(path, status_code=303)

FORM_ERRORS = {
    "Invalid CSRF token": "Форма устарела. Повторите отправку.",
    "Invalid login or password": "Проверьте формат логина и длину пароля.",
    "Login already exists": "Этот логин уже занят.",
    "Wrong credentials": "Неверный логин или пароль.",
    "Invalid old or new password": "Проверьте текущий пароль и длину нового.",
    "Flag must use CTF{...}": "Введите флаг в формате CTF{…}.",
    "Wait 3 seconds between submissions": "Подождите 3 секунды между попытками.",
    "Too many submissions, wait a minute": "Слишком много попыток. Подождите минуту.",
    "Invalid challenge": "Проверьте название, описание, категорию, сложность и количество баллов.",
    "Invalid CTF flag": "Флаг должен иметь формат CTF{…}.",
    "Invalid resource URL": "Укажите локальный путь, начинающийся с одного /.",
    "Built-in resources are configured at deployment": "Флаг и ресурс встроенного задания меняются при развёртывании.",
    "Database busy, try again": "База занята. Повторите отправку через несколько секунд.",
    "Login required": "Войдите в аккаунт.",
    "Demo reset is disabled": "Сброс доступен только в отдельном демонстрационном развёртывании.",
    "Admin only": "Это действие доступно администратору.",
    "Please change initial password": "Сначала смените начальный пароль.",
}


def form_error_page(request, status_code, detail, form, headers=None):
    path = request.url.path
    context = {"status_code": status_code, "headers": headers,
               "error": FORM_ERRORS.get(detail, "Проверьте заполнение формы и повторите отправку.")}
    with SessionLocal() as db:
        if path in ("/login", "/register"):
            return page(request, "auth.html", db, **context, action=path,
                        heading="Вход" if path == "/login" else "Регистрация",
                        username=str(form.get("username", ""))[:40])
        user = user_for(request, db)
        if path == "/change-password" and user:
            return page(request, "password.html", db, **context)
        challenge_match = re.fullmatch(r"/challenges/([0-9]{1,18})/submit", path)
        if user and not user.must_change_password and challenge_match:
            challenge = db.get(Challenge, int(challenge_match[1]))
            if challenge and challenge.is_published:
                return page(request, "challenge.html", db, **context, challenge=challenge)
        if user and user.is_admin and not user.must_change_password and path.startswith("/admin/"):
            safe_fields = ("title", "points", "category", "difficulty", "description", "resource_url", "is_published")
            values = {field: str(form[field])[:10000] for field in safe_fields if field in form}
            return admin_page(request, db, **context, failed_action=path, submitted=values)
        return page(request, "error.html", db, **context, error_status=status_code)


def wants_html(request):
    return "text/html" in request.headers.get("accept", "")


async def submitted_form(request):
    try:
        return await request.form()
    except StarletteHTTPException:
        return {}


@app.exception_handler(StarletteHTTPException)
async def html_errors(request, exc):
    if wants_html(request):
        if request.method == "GET":
            if exc.status_code == 401:
                return redirect("/login")
            if exc.status_code == 403 and exc.detail == "Please change initial password":
                return redirect("/change-password")
        if request.method == "POST":
            return await run_in_threadpool(form_error_page, request, exc.status_code,
                                           str(exc.detail), await submitted_form(request), exc.headers)
    return await http_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def validation_errors(request, exc):
    if wants_html(request) and request.method == "POST":
        return await run_in_threadpool(form_error_page, request, 422, "", await submitted_form(request))
    # Validation metadata can include raw submitted values.
    details = [{key: value for key, value in error.items() if key not in ("input", "ctx")}
               for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(details)})


@app.get("/health")
def health():
    with engine.connect() as con:
        con.exec_driver_sql("SELECT 1")
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    return page(request, "home.html", db, challenges=db.scalars(select(Challenge).where(Challenge.is_published.is_(True))).all())

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    return page(request, "auth.html", db, heading="Регистрация", action="/register")

@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    if not re.fullmatch(r"[a-zA-Z0-9_]{3,40}", username) or not 10 <= len(password) <= 256:
        raise HTTPException(400, "Invalid login or password")
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    try:
        db.flush()
        token = issue_session(db, user.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Login already exists")
    set_session(request, token)
    return redirect("/profile")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return page(request, "auth.html", db, heading="Вход", action="/login")

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(user.password_hash, password):
        raise HTTPException(401, "Wrong credentials")
    user_id, password_hash = user.id, user.password_hash
    db.rollback()
    begin_write(db)
    user = db.get(User, user_id)
    if not user or user.password_hash != password_hash:
        raise HTTPException(401, "Wrong credentials")
    digest = session_hash(request)
    if digest:
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest))
    token = issue_session(db, user_id)
    db.commit()
    set_session(request, token)
    return redirect("/change-password" if user.must_change_password else "/profile")

@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    digest = session_hash(request)
    if digest:
        begin_write(db)
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest))
        db.commit()
    request.session.clear()
    return redirect("/login")

@app.get("/change-password", response_class=HTMLResponse)
def password_page(request: Request, db: Session = Depends(get_db)):
    if not user_for(request, db):
        raise HTTPException(401)
    return page(request, "password.html", db)

@app.post("/change-password")
def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    user = user_for(request, db)
    if not user:
        raise HTTPException(401)
    if not 12 <= len(new_password) <= 256 or not verify_password(user.password_hash, old_password):
        raise HTTPException(400, "Invalid old or new password")
    old_hash = user.password_hash
    new_hash = hash_password(new_password)
    db.rollback()
    begin_write(db)
    user = require_user(request, db)
    if user.password_hash != old_hash:
        raise HTTPException(400, "Invalid old or new password")
    remove_bootstrap = user.must_change_password and user.is_admin and user.username == ADMIN_USERNAME
    user.password_hash = new_hash
    user.must_change_password = False
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    token = issue_session(db, user.id)
    db.commit()
    if remove_bootstrap and ADMIN_BOOTSTRAP_FILE:
        try:
            Path(ADMIN_BOOTSTRAP_FILE).unlink(missing_ok=True)
        except OSError:
            logging.getLogger(__name__).warning("Could not remove the expired bootstrap password file")
    set_session(request, token)
    return redirect("/profile")

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    solved = db.execute(select(Challenge.title, Challenge.points, Solve.solved_at).join(Solve, Solve.challenge_id == Challenge.id).where(Solve.user_id == user.id)).all()
    return page(request, "profile.html", db, solved=solved, score=sum(x.points for x in solved))

@app.get("/challenges", response_class=HTMLResponse)
def challenges(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    solved_ids = set(db.scalars(select(Solve.challenge_id).where(Solve.user_id == user.id)))
    items = db.scalars(select(Challenge).where(Challenge.is_published.is_(True)).order_by(Challenge.id)).all()
    return page(request, "challenges.html", db, challenges=items, solved_ids=solved_ids)

@app.get("/challenges/{challenge_id}", response_class=HTMLResponse)
def challenge_page(challenge_id: int, request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    challenge = db.get(Challenge, challenge_id)
    if not challenge or not challenge.is_published:
        raise HTTPException(404)
    message = request.query_params.get("message", "")
    if message not in ("Верно! Решение записано", "Неверный флаг"):
        message = ""
    return page(request, "challenge.html", db, challenge=challenge, message=message)

@app.post("/challenges/{challenge_id}/submit")
def submit(challenge_id: int, request: Request, flag: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    begin_write(db)
    user = require_user(request, db)
    challenge = db.get(Challenge, challenge_id)
    if not challenge or not challenge.is_published:
        raise HTTPException(404)
    if not re.fullmatch(r"CTF\{[^{}\r\n]{1,160}\}", flag):
        raise HTTPException(400, "Flag must use CTF{...}")
    last = db.scalar(select(func.max(Submission.submitted_at)).where(Submission.user_id == user.id, Submission.challenge_id == challenge_id))
    if last and utcnow() - last < timedelta(seconds=3):
        raise HTTPException(429, "Wait 3 seconds between submissions")
    recent_total = db.scalar(select(func.count()).select_from(Submission).where(Submission.user_id == user.id, Submission.submitted_at > utcnow() - timedelta(minutes=1)))
    if recent_total >= 20:
        raise HTTPException(429, "Too many submissions, wait a minute")
    correct = hmac.compare_digest(hash_flag(flag), challenge.flag_hash)
    db.add(Submission(user_id=user.id, challenge_id=challenge_id, is_correct=correct))
    if correct and not db.get(Solve, (user.id, challenge_id)):
        db.add(Solve(user_id=user.id, challenge_id=challenge_id))
    db.commit()
    message = "Верно! Решение записано" if correct else "Неверный флаг"
    return redirect("/challenges/" + str(challenge_id) + "?" + urlencode({"message": message}))

@app.get("/leaderboard", response_class=HTMLResponse)
def leaderboard(request: Request, db: Session = Depends(get_db)):
    score = func.coalesce(func.sum(Challenge.points), 0)
    recent = func.max(Solve.solved_at)
    scores = db.execute(select(User.username, score.label("score"), recent.label("last_solve")).select_from(User).outerjoin(Solve, Solve.user_id == User.id).outerjoin(Challenge, Challenge.id == Solve.challenge_id).where(User.is_admin.is_(False)).group_by(User.id).order_by(score.desc(), recent.asc(), User.username.asc())).all()
    return page(request, "leaderboard.html", db, scores=scores)

@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    return admin_page(request, db)


def admin_page(request, db, **kwargs):
    attempts = db.execute(select(Submission, User.username, Challenge.title).join(User).join(Challenge).order_by(Submission.id.desc()).limit(100)).all()
    solves = db.execute(select(Solve.solved_at, User.username, Challenge.title)
                        .join(User, Solve.user_id == User.id)
                        .join(Challenge, Solve.challenge_id == Challenge.id)
                        .order_by(Solve.solved_at.desc(), Solve.user_id, Solve.challenge_id).limit(100)).all()
    return page(request, "admin.html", db, challenges=db.scalars(select(Challenge).order_by(Challenge.id)).all(),
                attempts=attempts, solves=solves, builtin_ids=set(db.scalars(select(BuiltinChallenge.challenge_id))),
                demo_reset=DEMO_RESET, **kwargs)

def validate_challenge(category, difficulty, points, flag=None):
    if category not in ("Web", "Crypto") or difficulty not in ("easy", "medium", "hard") or not 1 <= points <= 1000:
        raise HTTPException(400, "Invalid challenge")
    if flag is not None and not re.fullmatch(r"CTF\{[^{}\r\n]{1,160}\}", flag):
        raise HTTPException(400, "Invalid CTF flag")

def validate_card(title, description, resource_url):
    if not title.strip() or not description.strip():
        raise HTTPException(400, "Invalid challenge")
    if resource_url and (not resource_url.startswith("/") or resource_url.startswith("//")
                         or "\\" in resource_url or any(ord(char) < 32 for char in resource_url)
                         or urlsplit(resource_url).netloc):
        raise HTTPException(400, "Invalid resource URL")


@app.post("/admin/challenges")
def create_challenge(request: Request, title: str = Form(...), category: str = Form(...), description: str = Form(...), points: int = Form(...), flag: str = Form(...), resource_url: str = Form(""), difficulty: str = Form("easy"), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    validate_challenge(category, difficulty, points, flag)
    validate_card(title, description, resource_url)
    db.add(Challenge(title=title[:140], category=category, description=description[:10000], points=points, flag_hash=hash_flag(flag), resource_url=resource_url[:300] or None, difficulty=difficulty, is_published=False))
    db.commit()
    return redirect("/admin")

@app.post("/admin/challenges/{challenge_id}/edit")
def edit_challenge(challenge_id: int, request: Request, title: str = Form(...), category: str = Form(...), description: str = Form(...), points: int = Form(...), flag: str = Form(""), resource_url: str = Form(""), difficulty: str = Form("easy"), is_published: bool = Form(False), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    begin_write(db)
    obj = db.get(Challenge, challenge_id)
    if not obj:
        raise HTTPException(404)
    builtin = db.scalar(select(BuiltinChallenge).where(BuiltinChallenge.challenge_id == challenge_id))
    if builtin and (flag or resource_url != (obj.resource_url or "")):
        raise HTTPException(400, "Built-in resources are configured at deployment")
    validate_challenge(category, difficulty, points, flag if flag else None)
    validate_card(title, description, resource_url)
    obj.title, obj.category, obj.description, obj.points = title[:140], category, description[:10000], points
    obj.resource_url, obj.difficulty, obj.is_published = resource_url[:300] or None, difficulty, is_published
    if flag:
        obj.flag_hash = hash_flag(flag)
    db.commit()
    return redirect("/admin")

@app.post("/admin/challenges/{challenge_id}/delete")
def delete_challenge(challenge_id: int, request: Request, confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    if confirmation != "DELETE":
        raise HTTPException(400, "Для удаления введите DELETE")

    begin_write(db)
    challenge = db.get(Challenge, challenge_id)
    if not challenge:
        raise HTTPException(404)
    if challenge.is_published:
        raise HTTPException(409, "Сначала скройте задание")
    if db.scalar(select(BuiltinChallenge.challenge_id).where(BuiltinChallenge.challenge_id == challenge_id)):
        raise HTTPException(409, "Встроенные задания можно только скрыть")
    if (db.scalar(select(Submission.id).where(Submission.challenge_id == challenge_id).limit(1)) is not None
            or db.scalar(select(Solve.user_id).where(Solve.challenge_id == challenge_id).limit(1)) is not None):
        raise HTTPException(409, "У задания есть история. Оставьте его скрытым, чтобы сохранить результаты")

    db.delete(challenge)
    db.commit()
    return redirect("/admin")


@app.post("/admin/reset")
def reset(request: Request, confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    if not DEMO_RESET:
        raise HTTPException(403, "Demo reset is disabled")
    if confirmation != "RESET":
        raise HTTPException(400)
    db.query(Submission).delete()
    db.query(Solve).delete()
    db.commit()
    return redirect("/admin")
