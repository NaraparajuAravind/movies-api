from sqlalchemy import Column, Integer, String, Float,ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True,index=True)
    username = Column(String(100), nullable=False, unique=True,index=True)
    hashed_password = Column(String)
    role_id = Column(Integer, ForeignKey("roles.id"))
    role_obj = relationship("Role", back_populates="users")

    movie_assignments = relationship("MovieAssignment", back_populates="user")


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True,index=True)
    name = Column(String,unique=True,index=True) # super admin, admin, editor, viewer
    description = Column(String,nullable=True)

    users = relationship("Users", back_populates="role_obj")


class Movie(Base):
    __tablename__ = "movies"
    id = Column(Integer, primary_key=True,index=True)
    title = Column(String,index=True)
    hero= Column(String)
    genre = Column(String)
    heroine = Column(String)
    year = Column(Integer)
    rating = Column(Float)
    created_by=Column(Integer, ForeignKey("users.id"))
    creator= relationship("Users")
    assignments = relationship("MovieAssignment", back_populates="movie")

class MovieAssignment(Base):
    __tablename__ = "movie_assignments"
    id = Column(Integer, primary_key=True,index=True)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

    movie = relationship("Movie", back_populates="assignments")
    user = relationship("Users", back_populates="movie_assignments")

class MovieFile(Base):
    __tablename__ = "movie_files"
    id = Column(Integer, primary_key=True,index=True)
    filename = Column(String,nullable=False)
    filepath = Column(String,nullable=False)
    filetype = Column(String,nullable=False)
    source = Column(String,nullable=False)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    uploaded_by = Column(Integer, ForeignKey("users.id"))