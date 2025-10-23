from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,Session

from sqlalchemy.orm import declarative_base
DATABASE_URL= "sqlite:///./NewApp.db"

# For SQLite in FastAPI, disable same-thread check.
engine = create_engine(DATABASE_URL,connect_args={'check_same_thread': False})

# Session factory
SessionLocal = sessionmaker(autocommit=False,autoflush=False,bind=engine)

# Base class for ORM models
Base = declarative_base()

def get_db():
    db:Session = SessionLocal()
    try:
        yield db
    finally:

        db.close()



