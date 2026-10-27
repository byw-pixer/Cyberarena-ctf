import hashlib, hmac, os, re, secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from models import Base, Challenge, Solve, Submission, User, utcnow

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberarena.db")
SECRET_KEY = os.getenv("SECRET_KEY", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
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
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def hash_flag(flag):
    return hmac.new(SECRET_KEY.encode(), flag.encode(), hashlib.sha256).hexdigest()

@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with SessionLocal.begin() as db:
        admin = db.scalar(select(User).where(User.username == ADMIN_USERNAME))
        if admin is None:
            db.add(User(username=ADMIN_USERNAME, password_hash=hasher.hash(ADMIN_PASSWORD), is_admin=True, must_change_password=True))
        elif not admin.is_admin:
            raise RuntimeError("Admin username already taken by player")
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="strict", max_age=28800)

def get_db():
    with SessionLocal() as db:
        yield db

def csrf(request):
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]

def validate_csrf(request, token):
    if not request.session.get("csrf") or not hmac.compare_digest(request.session["csrf"], token):
        raise HTTPException(403, "Invalid CSRF token")

def user_for(request, db):
    uid = request.session.get("uid")
    return db.get(User, uid) if isinstance(uid, int) else None

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

def page(request, filename, db, **kwargs):
    return templates.TemplateResponse(request, filename, {"user": user_for(request, db), "csrf": csrf(request), **kwargs})

def redirect(path):
    return RedirectResponse(path, status_code=303)

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
    user = User(username=username, password_hash=hasher.hash(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Login already exists")
    request.session.clear()
    request.session["uid"] = user.id
    return redirect("/profile")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    return page(request, "auth.html", db, heading="Вход", action="/login")

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token)
    user = db.scalar(select(User).where(User.username == username))
    try:
        valid = bool(user) and hasher.verify(user.password_hash, password)
    except VerificationError:
        valid = False
    if not valid:
        raise HTTPException(401, "Wrong credentials")
    request.session.clear()
    request.session["uid"] = user.id
    return redirect("/change-password" if user.must_change_password else "/profile")

@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
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
    try:
        valid = hasher.verify(user.password_hash, old_password)
    except VerificationError:
        valid = False
    if not valid or not 12 <= len(new_password) <= 256:
        raise HTTPException(400, "Invalid old or new password")
    user.password_hash = hasher.hash(new_password)
    user.must_change_password = False
    db.commit()
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
    return page(request, "challenge.html", db, challenge=challenge, message=request.query_params.get("message", ""))

@app.post("/challenges/{challenge_id}/submit")
def submit(challenge_id: int, request: Request, flag: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_user(request, db)
    validate_csrf(request, csrf_token)
    challenge = db.get(Challenge, challenge_id)
    if not challenge or not challenge.is_published:
        raise HTTPException(404)
    if not re.fullmatch(r"CTF\{[^{}\r\n]{1,160}\}", flag):
        raise HTTPException(400, "Flag must use CTF{...}")
    last = db.scalar(select(func.max(Submission.submitted_at)).where(Submission.user_id == user.id, Submission.challenge_id == challenge_id))
    if last and utcnow() - last < timedelta(seconds=3):
        raise HTTPException(429, "Wait 3 seconds between submissions")
    correct = hmac.compare_digest(hash_flag(flag), challenge.flag_hash)
    db.add(Submission(user_id=user.id, challenge_id=challenge_id, is_correct=correct))
    if correct and not db.get(Solve, (user.id, challenge_id)):
        db.add(Solve(user_id=user.id, challenge_id=challenge_id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
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
    attempts = db.execute(select(Submission, User.username, Challenge.title).join(User).join(Challenge).order_by(Submission.id.desc()).limit(100)).all()
    return page(request, "admin.html", db, challenges=db.scalars(select(Challenge).order_by(Challenge.id)).all(), attempts=attempts)

def validate_challenge(category, difficulty, points, flag=None):
    if category not in ("Web", "Crypto") or difficulty not in ("easy", "medium", "hard") or not 1 <= points <= 1000:
        raise HTTPException(400, "Invalid challenge")
    if flag is not None and not re.fullmatch(r"CTF\{[^{}\r\n]{1,160}\}", flag):
        raise HTTPException(400, "Invalid CTF flag")

@app.post("/admin/challenges")
def create_challenge(request: Request, title: str = Form(...), category: str = Form(...), description: str = Form(...), points: int = Form(...), flag: str = Form(...), resource_url: str = Form(""), difficulty: str = Form("easy"), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    validate_challenge(category, difficulty, points, flag)
    db.add(Challenge(title=title[:140], category=category, description=description[:10000], points=points, flag_hash=hash_flag(flag), resource_url=resource_url[:300] or None, difficulty=difficulty, is_published=False))
    db.commit()
    return redirect("/admin")

@app.post("/admin/challenges/{challenge_id}/edit")
def edit_challenge(challenge_id: int, request: Request, title: str = Form(...), category: str = Form(...), description: str = Form(...), points: int = Form(...), flag: str = Form(""), resource_url: str = Form(""), difficulty: str = Form("easy"), is_published: bool = Form(False), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    obj = db.get(Challenge, challenge_id)
    if not obj:
        raise HTTPException(404)
    validate_challenge(category, difficulty, points, flag if flag else None)
    obj.title, obj.category, obj.description, obj.points = title[:140], category, description[:10000], points
    obj.resource_url, obj.difficulty, obj.is_published = resource_url[:300] or None, difficulty, is_published
    if flag:
        obj.flag_hash = hash_flag(flag)
    db.commit()
    return redirect("/admin")

@app.post("/admin/reset")
def reset(request: Request, confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    validate_csrf(request, csrf_token)
    if confirmation != "RESET":
        raise HTTPException(400)
    db.query(Submission).delete()
    db.query(Solve).delete()
    db.commit()
    return redirect("/admin")
