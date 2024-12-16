from pydantic import BaseModel

class ValidationRequest(BaseModel):
    text: str

class RegistrationRequest(BaseModel):
    input_validators: list[str]
    output_validators: list[str]
    selected_model: str

class KeyDeletionRequest(BaseModel):
    key_id: str
