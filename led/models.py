from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from led import db, login_manager, app
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    classes = db.relationship('Classe', backref='supervisorClasse', lazy=True)
    eleves = db.relationship('Eleve', backref='supervisorEleve', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Classe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    niveau_classe = db.Column(db.String(15), nullable=False)
    serie_classe = db.Column(db.String(3), nullable=False)
    date_creation = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    annee_scolaire = db.Column(db.String(10), nullable=False)
    nom_classe = db.Column(db.String(50), nullable=False)
    classement =db.Column(db.String(2), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    eleves = db.relationship('Eleve', backref='classeDesEleves', lazy=True)


    def __repr__(self):
        return f"Classe('{self.nom_classe}', '{self.date_creation}','{self.annee_scolaire}')"

class Eleve(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prenom = db.Column(db.String(100), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    date_naissance = db.Column(db.String(15), nullable=False)
    num_telephone = db.Column(db.String(20), nullable=False)
    adresse = db.Column(db.String(300), nullable=False)
    date_inscription = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    classe_id = db.Column(db.Integer, db.ForeignKey('classe.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    


    def __repr__(self):
        return f"Eleve('{self.prenom}', '{self.nom}')"