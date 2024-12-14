from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from config import create_guard
from models import ValidationRequest

app = FastAPI()

async def validate_input(text: str):
    guard = create_guard(validator_type="input")
    validation_outcome = guard.parse(text)
    return validation_outcome

async def validate_output(text: str) -> None:
    guard = create_guard(validator_type="output")
    validation_outcome = guard.parse(text)
    return validation_outcome

@app.post("/validate_input")
async def post_validate_input(request: ValidationRequest):
    try:
        validation_outcome = await validate_input(request.text)
        return {"input_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@app.post("/validate_output")
async def post_validate_output(request: ValidationRequest):
    try:
        validation_outcome = await validate_output(request.text)
        return {"input_validation": validation_outcome}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")