from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField,SelectField,DateTimeField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError,Required,Regexp
from wtforms.fields.html5 import TelField,EmailField

from led.models import User,Classe,Eleve

######################################PARTIE   USER FORM    ##################################################################

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Email('Entrez un bon Email svp')])
    password = PasswordField('Password', validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide'))])
    remember = BooleanField('Se Rappeler de moi')
    submit = SubmitField('Connecter')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Length(min=2, max=20)])
    email = StringField('Email',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Email()])
    submit = SubmitField('Valider')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('nom utilisateur existe !Choississez un autre.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email existe déjà !Choississez un autre..')

class ForgetPwdForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Email()])
    submit = SubmitField('Valider')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Ce mail n existe pas. Creer un compte.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Mot de Passe', validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide'))])
    confirm_password = PasswordField('Confirmer Mot de Passe',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), EqualTo('password')])
    submit = SubmitField('Changer mot de passe')

class RegistrationForm(FlaskForm):
    username = StringField('Username',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Length(min=2, max=20,message='donnez username entre 2 à 20 caractere')])
    email = StringField('Email',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Email('Entrez un bon Email svp')])
    password = PasswordField('Mot de Passe', validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide'))])
    confirm_password = PasswordField('Confirmer Mot de Passe',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), EqualTo('password','Donnez le meme mot de passe')])
    submit = SubmitField('Valider')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Utilisateur existe. Donner un autre.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Donner un autre.')

######################################PARTIE  CLASSE FORM    ##############################################
class AjoutClasseForm(FlaskForm):

    # niveau_classe = SelectField('Niveau Classe',choices = [('sixieme','sixieme'),('cinquieme','cinquieme'),('quatrieme','quatrieme'),('troisieme','troisieme'),('seconde','seconde'),('premier','premier'),('Terminale','Terminale')])
    # classement= SelectField('Classement', choices = [('A','A'), ('B','B'),('C','C'),('D','D'),('E','E'), ('F','F')])
    # serie_classe= SelectField('Serie',choices = [('S1','S1'), ('S2','S2'), ('S3','S3'), ('T1','T1'), ('T2','T2'),('L1','L1'),('L2','L2'),("L'1","L'1"),("L'2","L'2"),('M1','M1')])
    # annee_scolaire = SelectField('Année Scolaire',choices = [])
    # submit = SubmitField('Valider')

    niveau_classe = StringField('Niveau Classe',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Regexp('^[a-zA-Z]+$',message='Donner des lettres seulement'), Length(min=7, max=11,message='donnez niveau classe entre 7 à 11 caracteres')])
    # classement=  StringField('classement:  par exemple A',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Regexp('^[A-Z]',message='Donnez une lettre Alphabétique exemple:A'), Length(min=1, max=1,message='un seul caractere')])
    classement= SelectField('Classement', choices = [('A','A'), ('B','B'),('C','C'),('D','D'),('E','E'), ('F','F'), ('G','G'), ('H','H'), ('I','I'), ('J','J')])
    # serie_classe= StringField('Serie: par exemple S2',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Regexp('^[A-Z0-9]',message='Donnez une lettre et un chiffre exemple:S2'), Length(min=2, max=2,message='donnez  2 caracteres')])
    serie_classe= SelectField('Serie',choices = [('S1','S1'), ('S2','S2'), ('S3','S3'), ('T1','T1'), ('T2','T2'),('L1','L1'),('L2','L2'),("L'1","L'1"),("L'2","L'2"),('M1','M1')])
    annee_scolaire = StringField('Année Scolaire',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Regexp('^20[0-9][0-9]/20[0-9][0-9]$',message=' respecter format:2018/2019'), Length(min=2, max=20,message='donnez niveau classe entre 2 à 20 caractere')])
    submit = SubmitField('Valider')




class SearchClasseForm(FlaskForm):
    nomClasse = StringField('Recherche Classe',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Length(min=2,message='Taper au moins entre 2 caracteres')])
    submit = SubmitField('Rechercher')

    def validate_nomClasse(self, nomClasse):
            classes=Classe.query.filter(Classe.nom_classe.contains("%s" % nomClasse))
            if classes is None :
                raise ValidationError('Classe non trouvée')



################################  PARTIE  eleve  ##################################################################"

class AjoutEleveForm(FlaskForm):
    prenom = StringField('Prenom',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Length(min=2, max=50,message='donnez Prenom entre 2 à 50 caractere')])
    nom = StringField('Nom',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Length(min=2, max=20,message='donnez Nom entre 2 à 20 caractere')])
    email = EmailField('Email',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Email('Entrez un bon Email svp')])
    dateNaissance =DateTimeField('Date de Naissance: jj/mm/aaaa', format='%d/%m/%Y', validators=[DataRequired()])
    tel = TelField('Telephone',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')), Length(min=9, max=9,message='donnez tel entre 2 à 20 caractere')])
    adresse = TextAreaField('Adresse', validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide'))])
    classeInscrit  = SelectField('Inscrit en Classe',choices = [])
    annee_scolaire = SelectField('Année Scolaire',choices = [] )
    submit = SubmitField('Valider')


class SearchEleveForm(FlaskForm):
    prenomeleve = StringField('Recherche Eleve:',validators=[DataRequired(message=('Champs obligatoire! Ne dois pas etre vide')),Length(min=2,message='Taper au moins entre 2 caracteres')])
    submit = SubmitField('Rechercher')

    def validate_prenomeleve(self, prenomeleve):
            eleves=Eleve.query.filter(Eleve.prenom.contains("%s" % prenomeleve))
            if eleves is None :
                raise ValidationError('Eleve non trouvé')