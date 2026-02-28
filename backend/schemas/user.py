from pydantic import BaseModel, EmailStr, field_validator


class UserRegister(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        # Minimum bar — in prod add entropy estimation (zxcvbn)
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            # Prevent DoS via extremely long inputs to the hash function
            raise ValueError("Password too long")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    is_active: bool

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """
    Only used for API/programmatic responses.
    Browser flows set tokens as cookies — they never appear in response bodies
    returned to the browser, preventing JS access.
    """
    token_type: str = "bearer"
    expires_in: int  # seconds
