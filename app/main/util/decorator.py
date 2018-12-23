from functools import wraps

from flask import request

from app.main.service.auth_service import Auth


'''
decorator for login required. Normal User role.
current_user must be added as a parameter to wrapped function
'''
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        data, status = Auth.get_current_user(request)
        token = data.get('data')

        if not token:
            return data, status

        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        data, status = Auth.get_current_user(request)
        token = data.get('data')

        if not token:
            return data, status

        admin = token.get('admin')

        if not admin:
            response = {
                'status' : 'fail',
                'message' : 'admin token required'
            }
            return response, 401

        return f(*args, **kwargs)

    return decorated


def dicrector_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        data, status = Auth.get_current_user(request)
        token = data.get('data')

        if not token:
            return data, status

        dicrector = token.get('dicrector')

        if not dicrector:
            response = {
                'status' : 'fail',
                'message' : 'dicrector token required'
            }
            return response, 401

        return f(*args, **kwargs)

    return decorated