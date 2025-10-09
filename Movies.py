
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Path, Query, Security, Form,File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import models, schemas
from database import get_db
from security import hashed_password, verify_password, create_access_token, verify_api_key, verify_token
import os,shutil
from fastapi.responses import FileResponse

# --- Auth Section ---
auth_router = APIRouter(prefix="/auth", tags=["Auth"])

@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), api_key: str = Security(APIKeyHeader(name="X-API-Key"))):
    verify_api_key(api_key)
    if db.query(models.Users).filter(models.Users.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    role_obj = db.query(models.Role).filter(models.Role.name == user.role).first()
    if not role_obj:
        raise HTTPException(status_code=400, detail="Invalid role")
    new_user = models.Users(
        username=user.username,
        hashed_password=hashed_password(user.password),
        role_id=role_obj.id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@auth_router.post("/token")
def login(username: str, password: str, db: Session = Depends(get_db), api_key: str = Security(APIKeyHeader(name="X-API-Key"))):
    verify_api_key(api_key)
    user = db.query(models.Users).filter(models.Users.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.username, "role": user.role_obj.name,"user_id": user.id})
    return {"access_token": token, "token_type": "bearer"}

# --- Authorization Dependency ---
API_KEY_NAME = "X-API-Key"
api_key_scheme = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

async def authorize(
    api_key: str = Security(api_key_scheme),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)
):
    if not api_key or not verify_api_key(api_key):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")
    payload = verify_token(credentials.credentials)
    return payload

# --- Users Section ---
users_router = APIRouter(prefix="/users", tags=["Users"])

@users_router.get("/", response_model=list[schemas.UserOut])
def get_all_users(db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role =auth["role"]
    query = db.query(models.Users).join(models.Role, models.Users.role_id == models.Role.id)
    if role == "viewer":
        query = query.filter(models.Role.name == "viewer", models.Users.id == auth.get("user_id"))
    elif role == "editor":
        query = query.filter(models.Role.name.in_(["viewer", "editor"]))
    elif role == "admin":
        query = query.filter(models.Role.name != "super admin")
    # super admin can see all users
    users = query.all()
    # Return list of dicts matching UserOut
    return [
        {"id": u.id, "username": u.username, "role": u.role_obj.name if u.role_obj else None}
        for u in users
    ]

@users_router.get("/{user_id}", response_model=schemas.UserOut)
def get_user_by_id(user_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    target_role = user.role_obj.name if user.role_obj else None
    requester_role = auth["role"]
    if requester_role == "viewer" and target_role != "viewer":
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    elif requester_role == "editor" and target_role not in ["viewer", "editor"]:
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    elif requester_role == "admin" and target_role == "super admin":
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")

    return {"id": user.id, "username": user.username, "role": target_role}

@users_router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    if auth["role"] not in ["super admin", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    db_user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(models.Role).filter(models.Role.id == db_user.role_id).first()
    if auth["role"] == "admin" and role and role.name == "super admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    for key, value in user_update.model_dump(exclude_unset=True).items():
        setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user

@users_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    if auth["role"] not in ["super admin", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    db_user = db.query(models.Users).filter(models.Users.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(models.Role).filter(models.Role.id == db_user.role_id).first()
    if auth["role"] == "admin" and role and role.name == "super admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    db.delete(db_user)
    db.commit()

# --- Movies Section ---
movies_router = APIRouter(prefix="/movies", tags=["Movies"])

@movies_router.post("/create", response_model=schemas.MovieOut, status_code=status.HTTP_201_CREATED)
def create_movie(movie: schemas.MovieCreate, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    if auth["role"] not in ["super admin", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden Insufficient permission")
    db_movie = models.Movie(**movie.model_dump(),created_by=auth["user_id"])
    db.add(db_movie)
    db.commit()
    db.refresh(db_movie)
    if auth["role"] == "super admin":
        users = db.query(models.Users).join(models.Role).filter(models.Role.name == "super admin").all()
    else:
        users = db.query(models.Users).join(models.Role).filter(models.Role.name.in_(["admin", "super admin"])).all()
    for user in users:
        db.add(models.MovieAssignment(movie_id=db_movie.id, user_id=user.id))
    db.commit()
    return db_movie

@movies_router.get("/", response_model=list[schemas.MovieOut])
def get_all_movies(db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role =auth["role"]
    user_id = auth["user_id"]
    if role in ["viewer", "editor"]:
        assignments = db.query(models.MovieAssignment).filter_by(user_id=user_id).all()
        movie_ids = [assignment.movie_id for assignment in assignments]
        movies= db.query(models.Movie).filter(models.Movie.id.in_(movie_ids)).all()
    else:
        assignments = db.query(models.MovieAssignment).filter_by(user_id=user_id).all()
        movie_ids = [assignment.movie_id for assignment in assignments]
        movies= db.query(models.Movie).filter(
            (models.Movie.id.in_(movie_ids)) | (models.Movie.created_by == user_id)
        ).all()
    return movies


@movies_router.get("/{movie_id}", response_model=schemas.MovieOut)
def get_one_movie(movie_id: int = Path(gt=0), db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    return movie

@movies_router.get("/year/{movie_year}", response_model=list[schemas.MovieOut])
def get_movie_by_year(movie_year: int = Path(ge=1990, le=2028), db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    movies = db.query(models.Movie).filter(models.Movie.year == movie_year).all()
    if not movies:
        raise HTTPException(status_code=404, detail=f"No movies found for year {movie_year}")
    return movies

@movies_router.get("/rating/{movie_rating}", response_model=list[schemas.MovieOut])
def get_movie_by_rating(movie_rating: float = Path(ge=0, le=10), db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    movies = db.query(models.Movie).filter(models.Movie.rating == movie_rating).all()
    if not movies:
        raise HTTPException(status_code=404, detail=f"No movies found for rating {movie_rating}")
    return movies

@movies_router.post("/assign",status_code=status.HTTP_201_CREATED)
def assign_movie(movie_id: int  ,user_id: int , is_assigned: bool ,db:Session = Depends(get_db), auth: dict = Depends(authorize)):
    if auth["role"] not in ["super admin", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    movie = db.query(models.Movie).filter_by(id=movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    user = db.query(models.Users).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if auth["role"] == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie_id,user_id=auth["user_id"]).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
    if is_assigned:
        if assignment:
            raise HTTPException(status_code=400, detail="Movie already assigned to user")
        new_assignment = models.MovieAssignment(movie_id=movie_id, user_id=user_id)
        db.add(new_assignment)
        db.commit()
        return {"message": "Movie assigned to user successfully"}
    else:
        if not assignment:
            raise HTTPException(status_code=400, detail="Movie not assigned to user")
        db.delete(assignment)
        db.commit()
        return {"message": "Movie unassigned from user successfully"}

@movies_router.put("/update/{movie_id}", response_model=schemas.MovieOut)
def update_movie(movie_id: int, movie: schemas.MovieCreate, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    db_movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    creator =db_movie.creator
    if auth["role"] == "admin":
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie_id,user_id=auth["user_id"]).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    elif auth["role"] == "super admin":
        pass
    else:
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")

    for key, value in movie.model_dump().items():
        setattr(db_movie, key, value)
    db.commit()
    db.refresh(db_movie)
    return db_movie

@movies_router.delete("/{movie_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_movie(movie_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    db_movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    creator =db_movie.creator
    if auth["role"] == "admin":
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie_id,user_id=auth["user_id"]).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    elif auth["role"] == "super admin":
        pass
    else:
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")

    db.delete(db_movie)
    db.commit()

# --- Files Section ---
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

files_router = APIRouter(prefix="/files", tags=["Files"])

from fastapi import UploadFile, File, Form, HTTPException, status
import os

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf", ".txt", ".ppt", ".pptx", ".doc", ".docx", ".xls"}

@files_router.post("/movies/{movie_id}/upload", response_model=schemas.MovieFileOut, status_code=status.HTTP_201_CREATED)
async def upload_movie_files(
    movie_id: int,
    source: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    auth: dict = Depends(authorize)
):
    role = auth["role"]
    user_id = auth["user_id"]

    movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")

    if role == "viewer":
        raise HTTPException(status_code=403, detail="Forbidden: insufficient permission")

    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden: project not assigned")

    if role == "editor":
        assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Forbidden: project not assigned")

    # Validate file extension
    _, ext = os.path.splitext(file.filename.lower())
    if file.content_type.startswith("image/"):
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Invalid image file type")
        filetype = "images"
    else:
        if ext not in ALLOWED_DOCUMENT_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Invalid document file type")
        filetype = "documents"

    save_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    movie_file = models.MovieFile(
        filename=file.filename,
        filepath=save_path,
        filetype=filetype,
        source=source,
        uploaded_by=user_id,
        movie_id=movie_id
    )
    db.add(movie_file)
    db.commit()
    db.refresh(movie_file)
    return movie_file
@files_router.get("/movies/{movie_id}/files", response_model=list[schemas.MovieFileOut])
def get_movie_files(movie_id: int, source: str | None = Query(default=None), db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    movie =db.query(models.Movie).filter(id =movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    if role == "viewer":
        assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie_id,user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Forbidden insufficient permission project not assigned")
    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie_id,user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot view files of super admin's movie")
    query = db.query(models.MovieFile).filter_by(movie_id =movie_id)
    if source:
        query = query.filter_by(models.MovieFile.source == source)
    return query.all()

@files_router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_movie_file(file_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    movie_file = db.query(models.MovieFile).filter_by(id = file_id).first()
    if not movie_file:
        raise HTTPException(status_code=404, detail="File not found")
    movie = db.query(models.Movie).filter_by(id = movie_file.movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Associated movie not found")
    if role == "viewer":
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie.id,user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot delete files of super admin's movie")
    if role == "editor":
        assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie.id,user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Editor can delete files only of assigned movies")

    if os.path.exists(movie_file.filepath):
        os.remove(movie_file.filepath)
    db.delete(movie_file)
    db.commit()

@files_router.get("/download/{file_id}")
def download_movie_file(file_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    movie_file = db.query(models.MovieFile).filter_by(id = file_id).first()
    if not movie_file:
        raise HTTPException(status_code=404, detail="File not found")
    movie = db.query(models.Movie).filter_by(id = movie_file.movie_id).first()
    if role == "viewer":
        assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie.id,user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="project not assigned")
    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie.id,user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot download files of super admin's movie")
    if role == "editor":
        assignment =db.query(models.MovieAssignment).filter_by(movie_id=movie.id,user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Editor can download files only of assigned movies")

    return FileResponse(path=movie_file.filepath, filename=movie_file.filename)

# ---Health Check---

Health_router = APIRouter(prefix="/health", tags=["Health"])

@Health_router.get("/")
def health_check():
    return {"status": "API is up and running"}

# --- Main App ---
app = FastAPI(
    title="Movies API",
    description="API for managing movies and users with role-based access.",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to your needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(movies_router)

app.include_router(files_router)

app.include_router(Health_router)
