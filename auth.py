from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security.api_key import APIKeyHeader
from database import get_db, User

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_validators(api_key: str = Depends(API_KEY_HEADER), db: Session = Depends(get_db)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key missing")

    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "input_validators": user.input_validators.split(","),
        "output_validators": user.output_validators.split(","),
    }
