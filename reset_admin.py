# reset_admin.py
from app import app, db
from models import User

with app.app_context():
    admin = User.query.filter_by(username="admin").first()
    if admin:
        admin.set_password("admin123")   
        admin.is_admin = True
        db.session.commit()
        print("✅ Admin password set to: admin123")
        print("Admin email:", admin.email)
    else:
        print("❌ Admin user not found.")
