# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80),  unique=True, nullable=False)
    email      = db.Column(db.String(150), unique=True, nullable=False)
    password   = db.Column(db.String(200), nullable=False)          # bcrypt hash
    role       = db.Column(db.String(20),  default='user')          # 'user' or 'admin'
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    scans   = db.relationship('Scan',   backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)

    def is_admin(self):
        return self.role == 'admin'


class Scan(db.Model):
    __tablename__ = 'scans'

    id          = db.Column(db.Integer, primary_key=True)
    share_token = db.Column(db.String(16), unique=True, nullable=False,
                            default=lambda: secrets.token_urlsafe(8))
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # null = guest
    url         = db.Column(db.Text,    nullable=False)
    risk_score  = db.Column(db.Integer, nullable=False)   # 0-100
    is_phishing = db.Column(db.Boolean, nullable=False)
    safe_prob   = db.Column(db.Float,   nullable=False)   # raw probability
    features_json = db.Column(db.Text,  nullable=True)    # JSON string of 30 features
    scanned_at  = db.Column(db.DateTime, default=datetime.utcnow)
    is_private  = db.Column(db.Boolean, default=False)    # if True, link won't work

    reports = db.relationship('Report', backref='scan', lazy=True)


class Report(db.Model):
    __tablename__ = 'reports'

    id         = db.Column(db.Integer, primary_key=True)
    scan_id    = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reason     = db.Column(db.String(50),  nullable=False)   # 'false_positive', 'false_negative', 'other'
    note       = db.Column(db.Text,        nullable=True)    # optional user explanation
    status     = db.Column(db.String(20),  default='pending')  # 'pending', 'reviewed', 'resolved'
    reported_at = db.Column(db.DateTime,   default=datetime.utcnow)


class Tip(db.Model):
    __tablename__ = 'tips'

    id          = db.Column(db.Integer, primary_key=True)
    category    = db.Column(db.String(80), nullable=False)
    title       = db.Column(db.String(120), nullable=False)
    body        = db.Column(db.Text, nullable=False)
    icon        = db.Column(db.String(80), nullable=False, default='fa-shield-halved')
    order       = db.Column(db.Integer, nullable=False, default=0)
    created_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
