
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

import uuid, jwt, datetime

from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Secret key to encode and decode jwt 
app.config['SECRET_KEY'] = 'somesecret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dashboard.db'

db = SQLAlchemy(app)


'''
Auth part to save user email and password and extra info in another table.
Including auth role level. Only admin can promote normal user to director.
And only director can access to other users info, including ESI info.
'''
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True, nullable=False)
    email = db.Column(db.String(50), unique = True, nullable=False)
    hashed_pass = db.Column(db.String(50), nullable=False)
    admin = db.Column(db.Boolean)
    director = db.Column(db.Boolean)

class UserInfo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    chinese_alias = db.Column(db.String(50), unique = True, nullable = False)
    english_alias = db.Column(db.String(50), unique = True, nullable = False)
    qq = db.Column(db.String(20), unique = True, nullable = False)

@app.route('/auth/login')
def login():
    return ''

'''
register end point.
take email and password from request body, and hash the password.
Then sort into DB.
'''
@app.route('/auth/register', methods=['POST'])
def register():
    #get data from request
    data = request.get_json()
    #hash password at server side
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id = str(uuid.uuid4()), email = data['email'], hashed_pass= hashed_password, admin = False, director = False)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Successfully registered'})
    except Exception as e:
        return jsonify({'message': str(e)}), 401


if __name__ == '__main__':
    app.run(debug = True)
