from pydantic import BaseModel
from typing import List, Optional

class ValidationRequest(BaseModel):
    text: str