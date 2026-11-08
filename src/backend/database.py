import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 실행 위치(현재 폴더)와 무관하게 이 파일 옆의 .env를 읽는다
load_dotenv(Path(__file__).resolve().parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL이 .env 파일에 없습니다.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=280, pool_size=5, max_overflow=5, pool_timeout=10)
SessionLocal = sessionmaker(bind=engine, autoflush=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
