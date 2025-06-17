from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Hashed password
    unique_key = db.Column(db.String(36), unique=True, nullable=False)  # UUID
    passwords = db.relationship('PasswordEntry', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login required methods
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purpose = db.Column(db.String(100), nullable=False)
    entry_username = db.Column(db.String(100), nullable=False)  # Renamed from user_id
    data = db.Column(db.Text, nullable=False)  # Encrypted username/password