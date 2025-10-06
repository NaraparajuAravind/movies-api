from database import Base, engine,SessionLocal
import models

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Tables created")

db=SessionLocal()

if db.query(models.Role).count() == 0:
    db.add_all([
        models.Role(id=1,name="super admin",description="Full access"),
        models.Role(id=2,name="admin",description="Admin access"),
        models.Role(id=3,name="editor",description="Edit access"),
        models.Role(id=4,name="viewer",description="View only"),
    ])
    db.commit()
    print("Seeded roles")
db.close()
print("Done")