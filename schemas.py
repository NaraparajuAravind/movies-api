from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional

CURRENT_YEAR = datetime.now().year

class MovieCreate(BaseModel):
    title: str = Field(min_length=3)
    hero: str = Field(min_length=2)
    genre: str = Field(min_length=5)
    heroine: str = Field(min_length=3)
    year: int = Field(ge=1990,le=CURRENT_YEAR+4)
    rating: float = Field(ge=0.0,le=10.0)



class MovieOut(MovieCreate):
    id: int
    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)
    role: str = Field(default="user")

class UserOut(BaseModel):
    id:int
    username: str
    role: str
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3)
    role: str | None = Field(default="viewer")

class MovieFileCreate(BaseModel):
    source : str =Field(...,description="Source of the movie file")
class MovieFileOut(BaseModel):
    id: int
    filename: str
    filetype: str
    source: str
    movie_id: int
    uploaded_by: int
    model_config = ConfigDict(from_attributes=True)

class UserAssignmentOut(BaseModel):
    user_id: int
    user_name: str
    movie_id: int
    movie_title: str
    assigned_by: str
    assigned_date: Optional[datetime]=None
    model_config = ConfigDict(from_attributes=True)


