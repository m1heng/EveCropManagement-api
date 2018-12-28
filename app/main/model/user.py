from .. import db
import datetime
from ..config import key
import jwt
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "user"

    #must be initialize at the moment of creating new user(register)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    director = db.Column(db.Boolean, nullable=False, default=False)
    fc = db.Column(db.Boolean, nullable=False, default=False)
    password_hash = db.Column(db.String(64), nullable=False)

    #will be updated after user's first login
    chinese_alias = db.Column(db.String(50), unique = True)
    english_alias = db.Column(db.String(50), unique = True)
    qq = db.Column(db.String(20), unique = True)


    @property
    def password(self):
        raise AttributeError('password: write-only')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_token(self):
        payload  = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45),
            'iat': datetime.datetime.utcnow(),
            'pid': self.public_id            
        }
        return jwt.encode(payload, key, algorithm='HS256')

    def __repr__(self):
        return "<User '{}'>".format(self.email)