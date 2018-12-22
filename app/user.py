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