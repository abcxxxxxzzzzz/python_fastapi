from datetime import datetime
from pydantic import BaseModel,EmailStr,constr


class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr
    photo: str

    class Config:
        orm_mode = True

class CreateUserSchema(UserBaseSchema):
    password: constr(min_length=5)
    passwordConfirm: str
    role: str = 'user'
    verified: bool = False


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=5)


class UserResponse(UserBaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime