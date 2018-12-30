import datetime

from .. import db

class SRP(db.Model):


    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable =False)
    killmail_id = db.Column(db.String(50), unique = True, nullable = False)
    submmited_on = db.Column(db.DateTime, nullable=False)
    reviewed_on = db.Column(db.DateTime)
    # 0: submitted, 1: approved, 2: declined
    decision = db.Column(db.SmallInteger, default=0)
    reimbursed_amount = db.Column(db.Integer, default=0)
    request_reason = db.Column(db.String(255))
    decision_reason = db.Column(db.String(255))