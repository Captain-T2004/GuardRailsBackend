from fastapi import FastAPI, HTTPException, Depends
from config import create_guard
from fastapi.middleware.cors import CORSMiddleware
from models import ValidationRequest, RegistrationRequest
from database import SessionLocal, User, get_db
from auth import get_validators
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis
from sqlalchemy.orm import Session
import secrets

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.on_event("startup")
async def startup_event():
    """
    Initialize FastAPILimiter during the FastAPI app's startup event.
    """
    redis_con = redis.from_url("redis://localhost", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_con)

@app.post("/register")
async def register_user(data: RegistrationRequest, db: Session = Depends(get_db)):
    # Generate a unique API key
    api_key = secrets.token_hex(16)

    # Save user data to the database
    user = User(
        api_key=api_key,
        input_validators=",".join(data.input_validators),
        output_validators=",".join(data.output_validators),
    )
    db.add(user)
    db.commit()
    return {"api_key": api_key}

@app.post("/validate_input", dependencies=[Depends(RateLimiter(times=100, seconds=86400))])
async def validate_input_endpoint(request: ValidationRequest, validators=Depends(get_validators)):
    try:
        print(validators)
        guard = create_guard(selected_validators=validators["input_validators"], validator_type="input")
        validation_outcome = guard.parse(request.text)
        return {"input_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@app.post("/validate_output", dependencies=[Depends(RateLimiter(times=100, seconds=86400))])
async def validate_output_endpoint(request: ValidationRequest, validators=Depends(get_validators)):
    try:
        guard = create_guard(selected_validators=validators["output_validators"], validator_type="output")
        validation_outcome = guard.parse(request.text)
        return {"output_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
