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

    # explicit relationships to disambiguate two FKs from MovieAssignment to Users
    # assignments where this user is the assignee
    movie_assignments = relationship(
        "MovieAssignment",
        foreign_keys="[MovieAssignment.user_id]",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # assignments created/made by this user
    assignments_made = relationship(
        "MovieAssignment",
        foreign_keys="[MovieAssignment.assigned_by]",
        back_populates="assigned_by_user",
        cascade="all, delete-orphan",
    )

    @property
    def role(self):
        """Expose a `role` attribute for Pydantic response models (returns role name)."""
        return self.role_obj.name if self.role_obj else None


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
    # make creator relationship explicit about which FK on this table refers to Users
    creator= relationship("Users", foreign_keys=[created_by])
    assignments = relationship("MovieAssignment", back_populates="movie", cascade="all, delete-orphan")

class MovieAssignment(Base):
    __tablename__ = "movie_assignments"
    id = Column(Integer, primary_key=True,index=True)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    assigned_by = Column(Integer,ForeignKey("users.id"))

    movie = relationship("Movie", back_populates="assignments")
    # relationship to the user who is assigned (assignee)
    user = relationship("Users", foreign_keys=[user_id], back_populates="movie_assignments")
    # relationship to the user who performed the assignment
    assigned_by_user = relationship("Users", foreign_keys=[assigned_by], back_populates="assignments_made")

class MovieFile(Base):
    __tablename__ = "movie_files"
    id = Column(Integer, primary_key=True,index=True)
    filename = Column(String,nullable=False)
    filepath = Column(String,nullable=False)
    filetype = Column(String,nullable=False)
    source = Column(String,nullable=False)
    movie_id = Column(Integer, ForeignKey("movies.id"))
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    # optional relationship to uploader
    uploaded_user = relationship("Users", foreign_keys=[uploaded_by])
