import datetime

from .. import db


class Character(db.Model):

    __tablename__ = "character"

    user_id = db.Column(db.Interger, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    esi_id = db.Column(db.Interger, primary_key=True, unique=True, nullable=False)
    add_date = db.Column(db.DateTime, nullable=False)
    esi_refresh_token = db.Column(db.String(255), unique = True, nullable = False)
    