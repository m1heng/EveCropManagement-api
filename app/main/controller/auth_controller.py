from flask import request
from flask_restplus import Resource

from app.main.service.auth_service import login_user, register_user, reset_pass, role_operation
from app.main.util.decorator import login_required, admin_required
from ..util.dto import AuthDto

api = AuthDto.api
user_auth = AuthDto.user_auth


@api.route('/login')
class Login(Resource):
    @api.expect(user_auth, validate=True)
    def post(self):
        # get the post data
        post_data = request.json
        return login_user(post_data)

@api.route('/register')
class Register(Resource):
    @api.expect(user_auth, validate=True)
    def post(self):
        post_data = request.json
        return register_user(post_data)

@api.route('/resetpassword')
class Resetpassword(Resource):
    @login_required
    def put(current_user, self):
        data =request.json
        return reset_pass(data, current_user)

@api.route('/roleoperation/<pid>'):
    @admin_required
    def put(self):
        data = request.json
        return role_operation(data, pid)

    
