from datetime import datetime
from models.user import db

# entry.py: SQLAlchemy model for storing encrypted password entries.
# Fields: username, website, encrypted values, safety key, notes, timestamps.

class PasswordEntry(db.Model):
    __tablename__ = 'password_entries'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    website = db.Column(db.String(255), nullable=False)
    final_password = db.Column(db.Text, nullable=False)
    original_decimal = db.Column(db.Text, nullable=False)
    safety_key = db.Column(db.Integer, nullable=False)
    note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<PasswordEntry {self.username} @ {self.website}>'
