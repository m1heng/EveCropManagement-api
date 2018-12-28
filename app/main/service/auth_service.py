import uuid
import datetime

from app.main import db
from app.main.model.user import User

def login_user(json_data):
    try:
        # fetch the user data
        user = User.query.filter_by(email=json_data.get('email')).first()
        if user and user.check_password(json_data.get('password')):
            auth_token = user.to_token()
            if auth_token:
                response_object = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'Authorization': auth_token.decode('UTF-8')
                }
                return response_object, 200
        else:
            response_object = {
                'status': 'fail',
                'message': 'email or password does not match.'
            }
            return response_object, 401

    except Exception as e:
        print(e)
        response_object = {
            'status': 'fail',
            'message': 'Try again'
        }
        return response_object, 500


def register_user(json_data):
    #check for user existence
    existing_user = User.query.filter_by(email=json_data['email']).first()
    if existing_user:
        response_body = {
            'status' : 'fail',
            'message' : 'User already exists.'
        }
        return response_body, 409

    #try add new user into db
    try:
        new_user = User(
            public_id = str(uuid.uuid4()),
            email = json_data['email'],
            registered_on = datetime.datetime.utcnow(),
            password = json_data['password'])
        db.session.add(new_user)
        db.session.commit()

        response_body = {
            'status' : 'success',
            'message' : 'Successfully registered. Please login.'
        }

        return response_body, 200

    except Exception as e:
        print(e)
        response_body = {
            'status': 'fail',
            'message': 'Try again'
        }
        return response_body, 500

"""
json_data: request body 
current_user: user object from login decrator
"""
def reset_pass(json_data, current_user):
    old_pass = json_data['old_pass']
    new_pass = json_data['new_pass']

    if not current_user.check_password(old_pass):
        response_body = {
            'status': 'fail',
            'message': 'old password not match'
        }
        return response_body, 401

    current_user.password = new_pass
    db.session.commit()
    response_body = {
        'status': 'success',
        'message': 'password resetted. please log in'
    }
    return response_body, 200

"""
json_data: role name and it's new value
target_user_pid: target user's publid id
"""
def role_operation(json_data,target_user_pid):

    target_user = User.query.filter_by(public_id = target_user_pid).first()

    if not target_user:
        response_body = {
            'status' : 'fail',
            'message' : 'target user not exists'
        }
        return response_body, 404

    op = json_data['director']

    if op :
        target_user.director = op


    response_body = {
        'status': 'success',
        'message' : 'tagert user role is changed'
    }
    return response_body, 200


def get_current_user(new_request):
    # get the auth token
    auth_token = new_request.headers.get('Authorization')
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=resp).first()
            response_object = {
                'status': 'success',
                'data': {
                    'user_id': user.id,
                    'email': user.email,
                    'admin': user.admin,
                    'registered_on': str(user.registered_on)
                }
            }
            return response_object, 200
        response_object = {
            'status': 'fail',
            'message': resp
        }
        return response_object, 401
    else:
        response_object = {
            'status': 'fail',
            'message': 'Provide a valid auth token.'
        }
        return response_object, 401

   