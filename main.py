from fastapi import Security, FastAPI, HTTPException, Depends, status, Header
from config import create_guard, parse_validation_output
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from models import ValidationRequest, RegistrationRequest, KeyDeletionRequest
from database import SessionLocal, User, Session as UserSession, get_db
from auth import get_validators, verify_key
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis
from sqlalchemy.orm import Session as SQLASession
import secrets
import uuid
import json
from jose import jwt
import requests
import os
from dotenv import load_dotenv

app = FastAPI()
AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN')
ALGORITHMS = ["RS256"]

bearer_scheme = HTTPBearer()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    redis_con = redis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_con)

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

@app.post("/register", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def register_user(data: RegistrationRequest, db: SQLASession = Depends(get_db), user=Depends(get_current_user)):

    existing_user = db.query(User).filter(User.api_key == user["sub"]).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")

    api_key = secrets.token_hex(16)
    new_user = User(
        sub=user["sub"],
        api_key=api_key,
        input_validators=",".join(data.input_validators),
        output_validators=",".join(data.output_validators),
        selected_model=data.selected_model
    )
    db.add(new_user)
    db.commit()
    return {"api_key": api_key}

@app.get("/prev_keys", dependencies=[Depends(RateLimiter(times=1000, seconds=60))])
async def get_prev_apis(db: SQLASession = Depends(get_db), user=Depends(get_current_user)):
    existing_keys = db.query(User).filter(User.sub == user["sub"]).all()

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

@app.post("/delete_keys", dependencies=[Depends(RateLimiter(times=1000, seconds=60))])
async def delete_prev_key(data: KeyDeletionRequest, db: SQLASession = Depends(get_db), user=Depends(get_current_user)):
    existing_key = db.query(User).filter(User.id == data.key_id).first()

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
        db.rollback()
        
        raise HTTPException(
            status_code=500, 
            detail="An error occurred while deleting the API key"
        )

@app.post("/start_session")
async def start_session(api_key = Depends(verify_key), db: SQLASession = Depends(get_db)):
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = str(uuid.uuid4())
    new_session = UserSession(session_id=session_id, user_id=user.id)
    db.add(new_session)
    db.commit()
    return {"session_id": session_id}

@app.post("/validate_input", dependencies=[Depends(RateLimiter(times=100, seconds=86400))])
async def validate_input_endpoint(
    request: ValidationRequest,
    session_id=Header(None, alias="X-Session-ID"),
    validators=Depends(get_validators),
    db: SQLASession = Depends(get_db),
):
    try:
        session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        if not session:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        guard = create_guard(selected_validators=validators["input_validators"], validator_type="input")
        validation_outcome = parse_validation_output(guard.parse(request.text))

        inputs = session.inputs or []
        inputs.append({"text": request.text, "validation_outcome": validation_outcome})
        session.inputs = inputs

        db.commit()

        return {"input_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@app.post("/validate_output", dependencies=[Depends(RateLimiter(times=100, seconds=86400))])
async def validate_output_endpoint(
    request: ValidationRequest,
    session_id=Header(None, alias="X-Session-ID"),
    validators=Depends(get_validators),
    db: SQLASession = Depends(get_db),
):
    try:
        session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        if not session:
            raise HTTPException(status_code=400, detail="Invalid session ID")

        guard = create_guard(selected_validators=validators["output_validators"], validator_type="output")
        validation_outcome = parse_validation_output(guard.parse(request.text))

        outputs = session.outputs or []
        outputs.append({"text": request.text, "validation_outcome": validation_outcome})
        session.outputs = outputs

        db.commit()

        return {"output_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")