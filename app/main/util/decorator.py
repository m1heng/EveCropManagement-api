from functools import wraps
import jwt

from flask import request

from ..config import key
from app.main.service.auth_service import Auth
from app.main.model.user import User


def vaildate_token(request_header):
    response_body = {
        'status' : 'fail',
        'message' : ''
    }

    if 'x-access-token' not in request_header:
        response_body['message'] = 'Token missing'
        return response_body, 401

    token = request_header['x-access-token']

    try:
        pid = jwt.decode(token, key)
        current_user = User.query.filter_by(public_id = pid).first()
    except Exception as e:
        response_body['message'] = e
        return response_body, 401

    if not current_user:
        response_body['message'] = 'fake token'
        return response_body, 401

    return current_user, 200

'''
decorator for login required. Normal User role.
current_user must be added as a parameter to wrapped function
'''
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user, status = vaildate_token(request.headers)
        if not isinstance(current_user, User):
            return current_user, status

        return f(current_user, *args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user, status = vaildate_token(request.headers)
        if not isinstance(current_user, User):
            return current_user, status

        if not current_user.admin:
            response_body = {
                'status' = 'fail',
                'message' = 'admin role required'
            }
            return response_body, 401

        return f(current_user,*args, **kwargs)

    return decorated


def dicrector_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user, status = vaildate_token(request.headers)
        if not isinstance(current_user, User):
            return current_user, status

        if not current_user.director:
            response_body = {
                'status' = 'fail',
                'message' = 'director role required'
            }
            return response_body, 401

        return f(current_user,*args, **kwargs)

    return decorated