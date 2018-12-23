from .. import db
import datetime
from ..config import key
import jwt
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    director = db.Column(db.Boolean, nullable=False, default=False)
    public_id = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(64), nullable=False)
    chinese_alias = db.Column(db.String(50), unique = True, nullable = False)
    english_alias = db.Column(db.String(50), unique = True, nullable = False)
    qq = db.Column(db.String(20), unique = True, nullable = False)


    @property
    def password(self):
        raise AttributeError('password: write-only')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def encode_auth_token(user_public_id):
        """
            Generates the Auth Token
            :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45),
                'iat': datetime.datetime.utcnow(),
                'sub': user_public_id
            }
            return jwt.encode(payload, key, algorithm='HS256')
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
            Decodes the auth token
            :param auth_token:
            :return: string
        """
        try:
            payload = jwt.decode(auth_token, key)
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    def __repr__(self):
        return "<User '{}'>".format(self.email)