from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Path, Query, Security, Form, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import or_
import models, schemas
from database import get_db
from security import hashed_password, verify_password, create_access_token, verify_api_key, verify_token
import os, shutil
from fastapi.responses import FileResponse

# --- Constants ---
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf", ".txt", ".ppt", ".pptx", ".doc", ".docx", ".xls"}

# --- Auth Section ---
auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db),
                api_key: str = Security(APIKeyHeader(name="X-API-Key"))):
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
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db),
          api_key: str = Security(APIKeyHeader(name="X-API-Key"))):
    verify_api_key(api_key)
    user = db.query(models.Users).filter(models.Users.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.username, "role": user.role_obj.name, "user_id": user.id})
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
    role = auth["role"]
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
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(get_db),
                auth: dict = Depends(authorize)):
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
    db_movie = models.Movie(**movie.model_dump(), created_by=auth["user_id"])
    db.add(db_movie)
    db.commit()
    db.refresh(db_movie)
    if auth["role"] == "super admin":
        users = db.query(models.Users).join(models.Role).filter(models.Role.name == "super admin").all()
    else:
        users = db.query(models.Users).join(models.Role).filter(models.Role.name.in_(["admin", "super admin"])).all()
    for user in users:
        # mark initial auto-assignments as created by the movie creator
        db.add(models.MovieAssignment(movie_id=db_movie.id, user_id=user.id, assigned_by=auth["user_id"]))
    db.commit()
    return db_movie


@movies_router.get("/", response_model=list[schemas.MovieOut])
def get_all_movies(db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    # viewer/editor: only assigned movies
    if role in ["viewer", "editor"]:
        assignments = db.query(models.MovieAssignment).filter_by(user_id=user_id).all()
        movie_ids = [assignment.movie_id for assignment in assignments]
        movies = db.query(models.Movie).filter(models.Movie.id.in_(movie_ids)).all()
    elif role == "admin":
        # Admins see movies created by any admin users (including themselves) and movies assigned to them
        # collect assigned movie ids
        assignments = db.query(models.MovieAssignment).filter_by(user_id=user_id).all()
        movie_ids = [assignment.movie_id for assignment in assignments]
        # find all admin user ids
        admin_user_ids = [r.id for r in db.query(models.Users).join(models.Role).filter(models.Role.name == "admin").all()]
        movies = db.query(models.Movie).filter(
            (models.Movie.created_by.in_(admin_user_ids)) | (models.Movie.id.in_(movie_ids))
        ).all()
    else:
        # super admin: see all movies
        movies = db.query(models.Movie).all()
    return movies

@movies_router.get('/user-assignments',response_model=list[schemas.UserAssignmentOut])
def get_user_assignments(db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    query = db.query(models.MovieAssignment).join(
        models.Users, models.MovieAssignment.user_id == models.Users.id
    ).join(
        models.Movie, models.MovieAssignment.movie_id == models.Movie.id
    ).join(
        models.Role, models.Users.role_id == models.Role.id
    )
    # Role-based visibility rules for assignments:
    # - viewer: see assignments for users with role 'viewer'
    # - editor: see assignments for users with role 'editor'
    # - admin: see assignments for non-super-admin users, plus any assignments related to movies the admin created or assignments the admin made
    # - super admin: see all assignments
    if role == "viewer":
        query = query.filter(models.Role.name == "viewer")  # fetch only viewer assignments
    elif role == "editor":
        query = query.filter(models.Role.name == "editor")  # fetch only editor assignments
    elif role == "admin":
        # Admins can see assignments for users except super admins, but also must see assignments for movies
        # they created and assignments they personally made.
        query = query.filter(
            or_(
                models.Role.name != "super admin",
                models.Movie.created_by == user_id,
                models.MovieAssignment.assigned_by == user_id,
            )
        )

    assignments = query.all() #super admin can see all assignments
    result = []
    for assignment in assignments:
        # Determine assigned_by name; prefer the explicit assigned_by_user, otherwise fall back to the movie creator
        assigned_by_name = None
        try:
            if getattr(assignment, 'assigned_by_user', None) and assignment.assigned_by_user:
                assigned_by_name = assignment.assigned_by_user.username
            else:
                # if there is no explicit assigned_by, use the movie creator (useful for initial auto-assignments)
                if getattr(assignment, 'movie', None) and getattr(assignment.movie, 'creator', None):
                    assigned_by_name = assignment.movie.creator.username
        except Exception:
            assigned_by_name = None

        result.append({
            "user_id": assignment.user_id,
            "username": assignment.user.username,
            "movie_id": assignment.movie_id,
            "movie_title": assignment.movie.title,
            "assigned_by": assigned_by_name,
            #"assigned_date": assignment.assigned_date
        })
    return result


@movies_router.get("/{movie_id}", response_model=schemas.MovieOut)
def get_one_movie(movie_id: int = Path(gt=0), db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    return movie


@movies_router.get("/year/{movie_year}", response_model=list[schemas.MovieOut])
def get_movie_by_year(movie_year: int = Path(ge=1990, le=2028), db: Session = Depends(get_db),
                      auth: dict = Depends(authorize)):
    movies = db.query(models.Movie).filter(models.Movie.year == movie_year).all()
    if not movies:
        raise HTTPException(status_code=404, detail=f"No movies found for year {movie_year}")
    return movies


@movies_router.get("/rating/{movie_rating}", response_model=list[schemas.MovieOut])
def get_movie_by_rating(movie_rating: float = Path(ge=0, le=10), db: Session = Depends(get_db),
                        auth: dict = Depends(authorize)):
    movies = db.query(models.Movie).filter(models.Movie.rating == movie_rating).all()
    if not movies:
        raise HTTPException(status_code=404, detail=f"No movies found for rating {movie_rating}")
    return movies


@movies_router.post("/assign", status_code=status.HTTP_201_CREATED)
def assign_movie(movie_id: int, user_id: int, is_assigned: bool, db: Session = Depends(get_db),
                 auth: dict = Depends(authorize)):
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
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=auth["user_id"]).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
    if is_assigned:
        if assignment:
            raise HTTPException(status_code=400, detail="Movie already assigned to user")
        new_assignment = models.MovieAssignment(
            movie_id=movie_id,
            user_id=user_id,
            assigned_by=auth["user_id"]
        )
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
def update_movie(movie_id: int, movie: schemas.MovieCreate, db: Session = Depends(get_db),
                 auth: dict = Depends(authorize)):
    db_movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not db_movie:
        raise HTTPException(status_code=404, detail="Movie not found")
    creator = db_movie.creator
    if auth["role"] == "admin":
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=auth["user_id"]).first()
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
    creator = db_movie.creator
    if auth["role"] == "admin":
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=auth["user_id"]).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    elif auth["role"] == "super admin":
        pass
    else:
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")

    db.delete(db_movie)
    db.commit()



# --- Files Section ---
files_router = APIRouter(prefix="/files", tags=["Files"])


@files_router.post("/movies/{movie_id}/upload", response_model=schemas.MovieFileOut,
                   status_code=status.HTTP_201_CREATED)
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

    # Create absolute path to avoid relative path issues
    save_path = os.path.abspath(os.path.join(UPLOAD_DIR, file.filename))

    print(f"💾 Saving file to: {save_path}")
    print(f"📁 Upload directory: {os.path.abspath(UPLOAD_DIR)}")

    try:
        with open(save_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        print(f"✅ File saved successfully: {save_path}")

        # Verify file was saved
        if os.path.exists(save_path):
            file_size = os.path.getsize(save_path)
            print(f"📏 File size: {file_size} bytes")
        else:
            print("❌ File verification failed - file not found after save")

    except Exception as e:
        print(f"❌ Error saving file: {e}")
        raise HTTPException(status_code=500, detail="Error saving file")

    movie_file = models.MovieFile(
        filename=file.filename,
        filepath=save_path,  # Store absolute path
        filetype=filetype,
        source=source,
        uploaded_by=user_id,
        movie_id=movie_id
    )
    db.add(movie_file)
    db.commit()
    db.refresh(movie_file)

    print(f"✅ File record created with ID: {movie_file.id}")
    return movie_file


@files_router.get("/movies/{movie_id}/files", response_model=list[schemas.MovieFileOut])
def get_movie_files(movie_id: int, source: str | None = Query(default=None), db: Session = Depends(get_db),
                    auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]

    movie = db.query(models.Movie).filter(models.Movie.id == movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Movie not found")

    if role == "viewer":
        assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Forbidden insufficient permission project not assigned")

    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie_id, user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot view files of super admin's movie")

    query = db.query(models.MovieFile).filter_by(movie_id=movie_id)
    if source:
        query = query.filter_by(source=source)
    return query.all()


@files_router.get("/images/{file_id}")
def get_image_file(file_id: int, db: Session = Depends(get_db)):
    """
    Public endpoint for serving images
    """
    try:
        movie_file = db.query(models.MovieFile).filter(models.MovieFile.id == file_id).first()
        if not movie_file:
            raise HTTPException(status_code=404, detail="File not found in database")

        print(f"🔍 Looking for image: {movie_file.filename}")
        print(f"📁 Stored filepath: {movie_file.filepath}")
        print(f"📊 File type: {movie_file.filetype}")

        # Only serve image files through this public endpoint
        if movie_file.filetype != "images":
            raise HTTPException(status_code=404, detail="Not an image file")

        # Check if file exists at stored path
        if not os.path.exists(movie_file.filepath):
            print(f"❌ File not found at stored path: {movie_file.filepath}")

            # Try to find the file using just the filename in uploads directory
            alternative_path = os.path.join(UPLOAD_DIR, movie_file.filename)
            print(f"🔄 Trying alternative path: {alternative_path}")

            if os.path.exists(alternative_path):
                print("✅ Found file at alternative path!")
                # Update the database with correct path
                movie_file.filepath = alternative_path
                db.commit()
            else:
                print("❌ File not found anywhere")
                # List all files in uploads directory for debugging
                upload_files = os.listdir(UPLOAD_DIR)
                print(f"📂 Files in uploads directory: {upload_files}")
                raise HTTPException(status_code=404, detail="File not found on server")

        # Determine content type based on file extension
        file_extension = os.path.splitext(movie_file.filename.lower())[1]
        media_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif'
        }

        media_type = media_types.get(file_extension, 'image/jpeg')

        print(f"✅ Serving image: {movie_file.filepath}")
        return FileResponse(
            path=movie_file.filepath,
            filename=movie_file.filename,
            media_type=media_type
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error serving image {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@files_router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_movie_file(file_id: int, db: Session = Depends(get_db), auth: dict = Depends(authorize)):
    role = auth["role"]
    user_id = auth["user_id"]
    movie_file = db.query(models.MovieFile).filter_by(id=file_id).first()
    if not movie_file:
        raise HTTPException(status_code=404, detail="File not found")
    movie = db.query(models.Movie).filter_by(id=movie_file.movie_id).first()
    if not movie:
        raise HTTPException(status_code=404, detail="Associated movie not found")
    if role == "viewer":
        raise HTTPException(status_code=403, detail="Forbidden insufficient permission")
    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie.id, user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot delete files of super admin's movie")
    if role == "editor":
        assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie.id, user_id=user_id).first()
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
    movie_file = db.query(models.MovieFile).filter_by(id=file_id).first()
    if not movie_file:
        raise HTTPException(status_code=404, detail="File not found")
    movie = db.query(models.Movie).filter_by(id=movie_file.movie_id).first()
    if role == "viewer":
        assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie.id, user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="project not assigned")
    if role == "admin":
        creator = movie.creator
        if creator.role_obj.name == "super admin":
            assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie.id, user_id=user_id).first()
            if not assignment:
                raise HTTPException(status_code=403, detail="Admin cannot download files of super admin's movie")
    if role == "editor":
        assignment = db.query(models.MovieAssignment).filter_by(movie_id=movie.id, user_id=user_id).first()
        if not assignment:
            raise HTTPException(status_code=403, detail="Editor can download files only of assigned movies")

    return FileResponse(path=movie_file.filepath, filename=movie_file.filename)


# Debug endpoints
@files_router.get("/debug/files")
def debug_files(db: Session = Depends(get_db)):
    """Debug endpoint to check all files and their paths"""
    files = db.query(models.MovieFile).all()
    result = []

    for file in files:
        file_info = {
            "id": file.id,
            "filename": file.filename,
            "stored_path": file.filepath,
            "filetype": file.filetype,
            "exists": os.path.exists(file.filepath),
            "movie_id": file.movie_id
        }

        # Check if file exists in uploads directory with just filename
        alternative_path = os.path.join(UPLOAD_DIR, file.filename)
        file_info["exists_in_uploads"] = os.path.exists(alternative_path)
        file_info["alternative_path"] = alternative_path

        result.append(file_info)

    return result


@files_router.post("/fix-file-paths")
def fix_file_paths(db: Session = Depends(get_db)):
    """Fix file paths for existing records"""
    files = db.query(models.MovieFile).all()
    fixed_count = 0

    for file in files:
        # If file doesn't exist at stored path, try uploads directory
        if not os.path.exists(file.filepath):
            alternative_path = os.path.join(UPLOAD_DIR, file.filename)
            if os.path.exists(alternative_path):
                print(f"Fixing path for {file.filename}: {file.filepath} -> {alternative_path}")
                file.filepath = alternative_path
                fixed_count += 1

    db.commit()
    return {"message": f"Fixed {fixed_count} file paths"}


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