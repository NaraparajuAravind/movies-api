from database import Base, engine,SessionLocal
import models
from sqlalchemy import inspect, text

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Tables created")

db=SessionLocal()

# Ensure roles exist
if db.query(models.Role).count() == 0:
    db.add_all([
        models.Role(id=1,name="super admin",description="Full access"),
        models.Role(id=2,name="admin",description="Admin access"),
        models.Role(id=3,name="editor",description="Edit access"),
        models.Role(id=4,name="viewer",description="View only"),
    ])
    db.commit()
    print("Seeded roles")

# Migration: ensure users table has role_id column and set defaults for existing users
insp = inspect(engine)
if 'users' in insp.get_table_names():
    with engine.begin() as conn:
        rows = conn.execute(text("PRAGMA table_info('users')")).fetchall()
        cols = [r[1] for r in rows]  # PRAGMA returns (cid, name, type, ...)
        if 'role_id' not in cols:
            print("Adding missing 'role_id' column to users table...")
            conn.execute(text("ALTER TABLE users ADD COLUMN role_id INTEGER;"))
            # set default role to viewer for existing users
            viewer = db.query(models.Role).filter(models.Role.name == 'viewer').first()
            if viewer:
                conn.execute(text(f"UPDATE users SET role_id = {viewer.id} WHERE role_id IS NULL;"))
            print("Updated existing users with default role_id")


db.close()
print("Done")