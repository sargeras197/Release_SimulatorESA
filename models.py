from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username}>"


# --- ДОДАЙ ЦЕ НИЖЧЕ ---


class TestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    test_name = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attempts = db.Column(db.Integer, default=1)
    successes = db.Column(db.Integer, default=0)
    fails = db.Column(db.Integer, default=0)
    time_spent = db.Column(db.Float, default=0)  # у секундах

    user = db.relationship("User", backref=db.backref("test_logs", lazy=True))
