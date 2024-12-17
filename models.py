import os
import re
from typing import Optional, Union
from fastapi import File, UploadFile
from pydantic import BaseModel, validator

class ValidationRequest(BaseModel):
    type: str
    userprompt: str
    systemprompt: str
    eventId: str
    attachments: Optional[UploadFile] = File(None)
    attachment_file_path: Optional[str] = None
    attachment_file_type: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True

    @validator("type")
    def validate_type(cls, value):
        if value not in ["input", "output"]:
            raise ValueError("type must be either 'input' or 'output'")
        return value

    @validator("attachment_file_path")
    def validate_filename(cls, attachment_file_path):
        if attachment_file_path:
            filename = attachment_file_path.split('/')[-1]
            
            if len(filename) > 255:
                raise ValueError("Invalid attachment_file_path length")
            
            if not re.match(r"^[a-zA-Z0-9_\-\.]+$", filename):
                raise ValueError("attachment_file_path contains invalid characters")
        
        return attachment_file_path

    @validator("attachment_file_type")
    def validate_file_type(cls, attachment_file_type):
        allowed_types = ["image", "document", "spreadsheet"]
        if attachment_file_type and attachment_file_type not in allowed_types:
            raise ValueError(f"Invalid file type. Allowed types are: {allowed_types}")
        return attachment_file_type

class RegistrationRequest(BaseModel):
    input_validators: list[str]
    output_validators: list[str]
    selected_model: str

class KeyDeletionRequest(BaseModel):
    key_id: str
