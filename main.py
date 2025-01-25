import os
import re
import json
import secrets
import uuid
from dotenv import load_dotenv
from fastapi import (
    FastAPI, Security, HTTPException, Depends, 
    status, Header, Form, File, UploadFile
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security.api_key import APIKeyHeader
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from jose import jwt
import redis.asyncio as redis
import requests
from sqlalchemy.orm import Session as SQLASession
from typing import Optional, Union
from config import create_guard, parse_validation_output
from models import ValidationRequest, RegistrationRequest, KeyDeletionRequest
from database import Api, Event as UserSession, get_db
from auth import get_validators, verify_key, verify_session

load_dotenv()
app = FastAPI()
bearer_scheme = HTTPBearer()
ALGORITHMS = ["RS256"]
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
UPLOAD_FILE_PATH = os.getenv('UPLOAD_FILE_PATH')
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        token = credentials.credentials

        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        jwks_response = requests.get(jwks_url)
        jwks_response.raise_for_status()
        jwks = jwks_response.json()
        

        unverified_header = jwt.get_unverified_header(token)

        rsa_key = next(
            (
                {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                for key in jwks["keys"]
            ),
            None
        )
        if not rsa_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Could not find appropriate key"
            )

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=os.getenv('AUTH0_AUDI'),
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token has expired"
        )

    except requests.RequestException:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Could not fetch JWKS"
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token"
        )

@app.on_event("startup")
async def startup_event():
    redis_con = redis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_con)

@app.post("/register", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def register_user(data: RegistrationRequest, db: SQLASession = Depends(get_db), user=Depends(get_current_user)):
    api_key = secrets.token_hex(16)
    new_key = Api(
        sub=user["sub"],
        api_key=api_key,
        input_validators=",".join(data.input_validators),
        output_validators=",".join(data.output_validators),
        selected_model=data.selected_model
    )
    db.add(new_key)
    db.commit()
    return {"api_key": api_key}

@app.get("/prev_keys", dependencies=[Depends(RateLimiter(times=1000, seconds=60))])
async def get_prev_apis(db: SQLASession = Depends(get_db), user=Depends(get_current_user)):
    existing_keys = db.query(Api).filter(Api.sub == user["sub"]).all()

    if not existing_keys:
        return {"message": "No API keys found for this user"}

    api_keys_data = [
        {
            "key_id": str(key.id),
            "api_key": key.api_key[:4],
            "input_validators": key.input_validators.split(","),
            "output_validators": key.output_validators.split(","),
            "selected_model": key.selected_model,
        }
        for key in existing_keys
    ]
    return {"api_keys": api_keys_data}

@app.get("/validators", dependencies=[Depends(RateLimiter(times=1000, seconds=60))])
async def get_all_validators(validators=Depends(get_validators),):

    return {
        "input_validators": validators["input_validators"],
        "output_validators": validators["output_validators"]
    }

@app.post("/delete_keys", dependencies=[Depends(RateLimiter(times=1000, seconds=60))])
async def delete_prev_key(data: KeyDeletionRequest, db: SQLASession = Depends(get_db), user=Depends(get_current_user)):
    existing_key = db.query(Api).filter(Api.id == data.key_id).first()

    if not existing_key:
        raise HTTPException(
            status_code=404, 
            detail="API key not found or you do not have permission to delete this key"
        )

    try:
        db.delete(existing_key)
        db.commit()
        return {
            "status": "success", 
            "message": "API key successfully deleted"
        }

    except Exception as e:
        print(e)
        db.rollback()
        
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while deleting the API key"
        )

@app.post("/start_event")
async def start_event(api_key = Depends(verify_key), db: SQLASession = Depends(get_db)):
    api_user = db.query(Api).filter(Api.api_key == api_key).first()
    if not api_user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    event_id = str(uuid.uuid4())
    new_session = UserSession(event_id=event_id, api_id=api_user.id)
    db.add(new_session)
    db.commit()
    return {"event_id": event_id}


@app.post("/validate", dependencies=[Depends(RateLimiter(times=1000000000, seconds=86400))])
async def validation_endpoint(
    type: str = Form(...),
    userprompt: str = Form(...),
    systemprompt: str = Form(...),
    eventId: str = Form(...),
    attachments: Optional[UploadFile] = File(None),
    attachment_file_path: Optional[str] = Form(None),
    attachment_file_type: Optional[str] = Form(None),
    db: SQLASession = Depends(get_db),
    validators=Depends(get_validators),
    api_key: str = Depends(API_KEY_HEADER),
):
    try:
        request_dict = {
            "type": type,
            "userprompt": userprompt,
            "systemprompt": systemprompt,
            "eventId": eventId,
            "attachments": attachments,
            "attachment_file_path": attachment_file_path,
            "attachment_file_type": attachment_file_type
        }
        
        request = ValidationRequest(**{k: v for k, v in request_dict.items() if v is not None})
        event = db.query(UserSession).filter(UserSession.event_id == eventId).first()
        verification = await verify_session(event_id=eventId, api_key=api_key, db=db)
        if not event or not verification:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        event = UserSession(
            event_id=request.eventId,
            api_id=db.query(Api).filter(Api.api_key == api_key).first().id,
            results=[],
        )
        db.add(event)
        db.commit()
        attachment_file_path = None
        if request.attachments:
            filename = str(uuid.uuid4())+request.attachments.filename
            attachment_file_path = f"{UPLOAD_FILE_PATH}{filename}"
            os.makedirs(os.path.dirname(attachment_file_path), exist_ok=True)
            
            with open(attachment_file_path, "wb") as f:
                content = await request.attachments.read()
                f.write(content)
        if(request.type == "input"): guard = create_guard(selected_validators=validators["input_validators"], validator_type="input")
        else: guard = create_guard(selected_validators=validators["output_validators"], validator_type="output")
        validation_outcome = parse_validation_output(
            guard.parse(f"{request.userprompt}\n{request.systemprompt}"),
        )
        results = event.results or []
        results.append({
            "type": request.type,
            "userprompt": request.userprompt,
            "systemprompt": request.systemprompt,
            "validation_outcome": validation_outcome,
            "attachment_file_path": attachment_file_path,
            "attachment_file_type": request.attachment_file_type,
        })
        event.results = results
        db.commit()

        return {"validation_outcome": validation_outcome}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")