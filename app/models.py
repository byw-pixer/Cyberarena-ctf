from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Challenge(Base):
    __tablename__ = 'challenges'
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(140))
    category: Mapped[str] = mapped_column(String(20))
    difficulty: Mapped[str] = mapped_column(String(20), default='easy')
    description: Mapped[str] = mapped_column(Text)
    points: Mapped[int] = mapped_column(Integer)
    flag_hash: Mapped[str] = mapped_column(String(64))
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    resource_url: Mapped[str | None] = mapped_column(String(300), nullable=True)

class Submission(Base):
    __tablename__ = 'submissions'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    challenge_id: Mapped[int] = mapped_column(ForeignKey('challenges.id'))
    submitted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    is_correct: Mapped[bool] = mapped_column(Boolean)

class Solve(Base):
    __tablename__ = 'solves'
    __table_args__ = (UniqueConstraint('user_id', 'challenge_id', name='unique_solve'),)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), primary_key=True)
    challenge_id: Mapped[int] = mapped_column(ForeignKey('challenges.id'), primary_key=True)
    solved_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
