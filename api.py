
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


class UserESI(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    char_name = db.Column(db.String(50), unique = True, nullable = False)
    char_id = db.Column(db.String(50), unique =True, nullable =False)
    refresh_token = db.Column(db.String(255), unique = True, nullable = False)

class SRP(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable =False)
    km_id = db.Column(db.String(50), unique = True, nullable = False)
    decision = db.Column(db.Boolean)
    amount = db.Column(db.Integer)
    request_reason = db.Column(db.String(255))
    decision_reason = db.Column(db.String(255))

class FleetRecord(db.Model):
    __tablename__  = 'FleetRecord'
    id = db.Column(db.Integer, primary_key = True)
    fc_user_id = db.Column(db.String(50), nullable = False)
    fleet_doctrine = db.Column(db.String(50), nullable = False)

class FleetMemberRecord(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    fleet_id = db.Column(db.Integer, db.ForeignKey('FleetRecord.id'), nullable = False)
    char_id  = db.Column(db.String(50), nullable = False)
    ship_type = db.Column(db.String(50), nullable = False)


'''
decorator for login required. Normal User role.
current_user must be added as a parameter to wrapped function
'''
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


'''
login end point.
Return jwt token with public id encoded.
'''
@app.route('/auth/login')
def login():
    auth = request.authorization

    print(auth)

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Username or Password mismatch!"'})

    if check_password_hash(user.hashed_pass, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Username or Password mismatch!"'})

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
        return jsonify({'message': str(e)}), 403

'''
reset password with reenter current password. 
Login required.
'''
@app.route('/auth/resetpassword', methods=['PUT'])
@login_required
def resetPassword(current_user):
    data = request.get_json()
    current_password = data['current_password']
    new_password = data['new_password']

    if not check_password_hash(current_user.hashed_pass, current_password):
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Username or Password mismatch!"'})
    current_user.hashed_pass = generate_password_hash(new_password, method='sha256')
    db.session.commit()
    return jsonify({'message' : 'Successfully changed password, Login again'})

'''
update a user's role, including promote to director or demote.
Admin role is required with the logined user.
Admin role can not be updated by this end point.
'''
@app.route('/auth/updateRole', methods=['PUT'])
@login_required
def updateRole(current_user):
    if not current_user.admin:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Admin role required"'})

    target_user_public_id = request.args.get('target_user_public_id')
    target_user = User.query.filter_by(public_id = target_user_public_id).first()

    if not target_user:
        return jsonify({'message' : 'Target User can not be found'}), 404

    target_user.director = True if request.args.get('operation') == 'promote' else False
    db.session.commit()

    return jsonify({'message' : 'Successfully Promoted User'})

'''
update userinfo, create new info if not exit
'''
@app.route('/userinfo', methods=['GET','PUT', 'POST'])
@login_required
def user_updateInfo(current_user):
    #create new userinfo
    if request.method == 'POST':
        data = request.get_json()

        new_userinfo = UserInfo(user_id = current_user.id, chinese_alias = data['chinese_alias'], english_alias = data['english_alias'], qq = data['qq'])
        try:
            db.session.add(new_userinfo)
            db.session.commit()
            return jsonify({'message': 'Successfully created userinfo'})
        except Exception as e:
            return jsonify({'message' : str(e)}), 400
        
    elif request.method == 'PUT':
        userinfo = UserInfo.query.filter_by(user_id = current_user.id).first()

        if not userinfo:
            return jsonify({'message' : 'UserInfo isn\'t created'}), 404

        data = request.get_json()
        new_qq = data['qq']
        new_chinese_alias = data['chinese_alias']
        new_english_alias = data['english_alias']

        if new_qq:
            userinfo.qq = new_qq

        if new_chinese_alias:
            userinfo.chinese_alias = new_chinese_alias

        if new_english_alias:
            userinfo.english_alias = new_english_alias

        db.session.commit()

        return jsonify({'message':'Successfully updated userinfo'})
    elif request.method == 'GET':
        current_userinfo = UserInfo.query.filter_by(user_id = current_user.id).first()

        if not current_userinfo:
            return jsonify({'message' : 'userinfo not found'}), 404

        infodata = {}
        infodata['qq'] = current_userinfo.qq
        infodata['english_alias'] = current_userinfo.english_alias
        infodata['chinese_alias'] = current_userinfo.chinese_alias

        return jsonify({'userinfo' : infodata})


if __name__ == '__main__':
    app.run(debug = True)
