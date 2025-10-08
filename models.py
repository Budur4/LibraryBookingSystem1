from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


    # كلمات المرور
    def set_password(self, password):
        # نعمل strip للـ password قبل الهاش
        self.password_hash = generate_password_hash(password.strip())

    def check_password(self, password):
        return check_password_hash(self.password_hash, password.strip())

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=1)
    bookings = db.relationship('Booking', backref='resource', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', backref='bookings', lazy=True)
