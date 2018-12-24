from flask import request
from flask_restplus import Resource

from app.main.service.auth_service import Auth
from ..util.dto import AuthDto

api = AuthDto.api
user_auth = AuthDto.user_auth


@api.route('/login')
class Login(Resource):
    @api.expect(user_auth, validate=True)
    def post(self):
        # get the post data
        post_data = request.json
        return Auth.login_user(data=post_data)

@api.route('/register')
class Register(Resource):
    @api.expect(user_auth, validate=True)
    def post(self):
        post_data = request.json
        return Auth.register_user(data=post_data)

@api.route('/resetpassword')
class Resetpassword(Resource):
    def post(self):
        post_data =request.json
        return Auth.resetpassword(data=post_data)

    
