from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security.api_key import APIKeyHeader
from database import get_db, Api, Event as UserSession

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_validators(api_key: str = Depends(API_KEY_HEADER), db: Session = Depends(get_db)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key missing")

    api = db.query(Api).filter(Api.api_key == api_key).first()
    if not api:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "input_validators": api.input_validators.split(","),
        "output_validators": api.output_validators.split(","),
    }

async def verify_key(api_key: str = Depends(API_KEY_HEADER), db: Session = Depends(get_db)):
    if not api_key:
        return None

    api = db.query(Api).filter(Api.api_key == api_key).first()
    if not api:
        return None

    return api_key

async def verify_session(event_id: str, api_key: str, db: Session):
    session = db.query(UserSession).filter(UserSession.event_id == event_id).first()
    api = db.query(Api).filter(Api.api_key == api_key).first()
    if not api or not session or session.api_id != api.id:
        return None
    return event_id