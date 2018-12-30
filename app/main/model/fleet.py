
import Datetime

from .. import db


class Fleet(db.Model):

    __tablename__ = 'fleet'

    id = db.Column(db.Integer, primary_key = True)
    fc_char_esi_id = db.Column(db.Integer, db.ForeignKey('character.esi_id'), nullable=False)
    fc_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recorded_on = db.Column(db.Datetime)
     



class FleetMember(db.Model):

    fleet_id
    user_id
