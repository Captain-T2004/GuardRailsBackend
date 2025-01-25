import os
from dotenv import load_dotenv
from sqlalchemy import (
    Column, Integer, String, Text, 
    ForeignKey, DateTime, create_engine
)
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from sqlalchemy_utils import database_exists, create_database

load_dotenv()

SQLALCHEMY_DATABASE_URL = f"postgresql://{os.getenv('DATABASE_USER')}:{os.getenv('DATABASE_PASSWORD')}@{os.getenv('DATABASE_HOST')}:{os.getenv('DATABASE_PORT')}/{os.getenv('DATABASE_NAME')}?sslmode=require"

Base = declarative_base()
engine = create_engine(SQLALCHEMY_DATABASE_URL)
if not database_exists(engine.url): create_database(engine.url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Api(Base):
    __tablename__ = "apis"

    id = Column(Integer, primary_key=True, index=True)
    sub = Column(String, nullable=False)
    api_key = Column(String, unique=True, nullable=False, index=True)
    input_validators = Column(Text, nullable=False)
    output_validators = Column(Text, nullable=False)
    selected_model = Column(String, nullable=False)

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, nullable=False)
    api_id = Column(Integer, nullable=False)
    time_stamp = Column(DateTime(timezone=True), server_default=func.now())
    results = Column(JSON, default=[])

Base.metadata.create_all(bind=engine)
