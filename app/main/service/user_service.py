import uuid
import datetime

from app.main import db
from app.main.model.user import User
from app.main.util.resp import stdJSONresp

def update_user_info(data, current_user, target_user_pid):
    #check if target pid matches current_user, normal user can only change own info except admin 
    if current_user.public_id != target_user_pid and not current_user.admin:
        return stdJSONresp('fail', 'Unauthrized', 401)

    chinese_alias = data['chinese_alias']
    english_alias = data['english_alias']
    qq = data['qq']

    target_user = User.query.filter_by(public_id = target_user_pid).first()

    if not target_user:
        return stdJSONresp('fail', 'user not found', 404)

    if chinese_alias:
        target_user.chinese_alias = chinese_alias

    if english_alias:
        target_user.english_alias = english_alias

    if qq:
        target_user.qq = qq

    return stdJSONresp('success', 'Userinfo updated', 200)


def get_all_users():
    return User.query.all()


def get_a_user(public_id):
    return User.query.filter_by(public_id=public_id).first()

