import os
import re
from datetime import datetime
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort,jsonify,session
from led import app, db, bcrypt, mail
from led.forms import (RegistrationForm, LoginForm,SearchClasseForm, UpdateAccountForm, 
                       ForgetPwdForm,ResetPasswordForm,AjoutClasseForm,AjoutEleveForm,SearchEleveForm)
from led.models import User,Classe,Eleve
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

################################  PARTIE  USERR ##################################################################"
@app.route('/register',methods = ["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Votre compte a été créé! Connectez-vous maintenant', 'success')
        return  redirect(url_for('login'))
    return render_template("users/register.html",form=form)

@app.route('/',methods = ["POST", "GET"])
@app.route('/led',methods = ["POST", "GET"])
@app.route("/login",methods = ["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Connexion echouee.Verifier votre email et password', 'danger')
    return render_template("users/login.html",form=form)




@app.route("/account",methods = ["POST", "GET"])
@login_required
def account():
    form=UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Votre compte a été mis à jour!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    
    return render_template('users/account.html',form=form)



def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='mbaye.sadahta@gmail.com',
                  recipients=[user.email])
    msg.body = f'''Pour reinitialiser votre mot de passe Cliquez sur ce lien:
{url_for('reset_token', token=token, _external=True)}
Sinon ignorer le et aucun changement ne s'opérera  sur les identifients du compte.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def forget_pwd():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ForgetPwdForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Un email vous est envoyé suivre les instructions pour reinitialiser votre mot de passe .', 'info')
        return redirect(url_for('login'))
    return render_template('users/forget_pwd.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Jeton Invalide', 'warning')
        return redirect(url_for('forget_pwd'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Votre mot de passe a été reinitialisé! Connectez-Vous', 'success')
        return redirect(url_for('login'))
    return render_template('users/reset_token.html', title='Reset Password', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


################################  PARTIE  CLASSE  ##################################################################"


@app.route('/led/new/classe', methods=['GET', 'POST'])
@login_required
def new_classe():
   
    form=AjoutClasseForm()
    # if request.method == 'POST':
    if form.validate_on_submit():
        niveau_classe=form.niveau_classe.data
        serie_classe=form.serie_classe.data
        classement=form.classement.data
        annee_scolaire=form.annee_scolaire.data
        nom_classe=niveau_classe+'-'+serie_classe+'-'+classement
        classe=Classe.query.filter_by(nom_classe=nom_classe,annee_scolaire=annee_scolaire).first()
        if classe:
            flash("Cette Classe est  déja créée","danger")
            return redirect(url_for("new_classe"))
        classe = Classe(niveau_classe=form.niveau_classe.data,serie_classe=form.serie_classe.data,
                        annee_scolaire=form.annee_scolaire.data,supervisorClasse=current_user,
                        nom_classe=nom_classe,classement=form.classement.data)
        db.session.add(classe)
        db.session.commit()
        flash('Votre classe a été créée!', 'success')
        return  redirect(url_for('index_classe'))
    elif request.method == 'GET': 
        form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
        # form.annee_scolaire.choices=[(anneeScolaire,anneeScolaire)]
    return render_template('classes/new_classe.html',title="Ajout Classe",form=form,legend="Ajout Classe")


@app.route('/led/classes')
def index_classe():
    form=SearchClasseForm()
    page=request.args.get('page',1,type=int)
    # classes=Classe.query.all()
    classes=Classe.query.order_by(Classe.date_creation.desc()).paginate(page=page,per_page=5)
    return render_template('classes/index_classe.html',classes=classes, form=form)

@app.route('/serie/<string:niveau>')
def serie(niveau):
    # cities = City.query.filter_by(state=state).all()
    
    serieArray = []

    # for city in cities:
    #     cityObj = {}
    #     cityObj['id'] = city.id
    #     cityObj['name'] = city.name
    #     cityArray.append(cityObj)

    # return jsonify({'cities' : cityArray})
    if niveau == 'sixieme' or niveau =='cinquieme' or niveau == 'quatrieme' or niveau == 'troisieme':
        serieArray=["M1"]
    else:
        serieArray=["S1", "S2","S3","L1","L2","L'1","L'2","T1","T2"]
    return jsonify({'series' : serieArray})

 
@app.route('/led/classe/show/<int:classe_id>')
def show_classe(classe_id):                             
    classe=Classe.query.get_or_404(classe_id)
    return render_template('classes/show_classe.html',classe=classe)



@app.route('/led/classe/update/<int:classe_id>',methods=['POST','GET'])
@login_required
def update_classe(classe_id):
    classe=Classe.query.get_or_404(classe_id)

    if classe.supervisorClasse!= current_user:
        abort(404)
    form=AjoutClasseForm() 
    # if request.method =='POST' :
    if form.validate_on_submit():
        niveau_classe = form.niveau_classe.data
        serie_classe=form.serie_classe.data
        annee_scolaire=form.annee_scolaire.data
        classement=form.classement.data
        nom_classe=form.niveau_classe.data+'-'+form.serie_classe.data+'-'+form.classement.data
        if classe.nom_classe == nom_classe and classe.annee_scolaire==annee_scolaire :
            flash("Une Classe portant se nom existe déja ou ne valider pas si aucune modification n'a été faite ","danger")
            return redirect(url_for("update_classe",classe_id=classe.id))
        classe.niveau_classe = niveau_classe
        classe.serie_classe=serie_classe
        classe.annee_scolaire=annee_scolaire
        classe.classement=classement
        classe.nom_classe=nom_classe
        db.session.commit()
        flash('Classe a été modifiée','success')
        return redirect(url_for('index_classe'))
    elif request.method=='GET':
        form.niveau_classe.data=classe.niveau_classe
        form.serie_classe.data=classe.serie_classe
        form.classement.data = classe.classement
        form.annee_scolaire.data = classe.annee_scolaire
        # form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()]
        # form.annee_scolaire.choices=[(anneeScolaire,anneeScolaire)]

    return render_template('classes/new_classe.html',title="Modifier Classe",form=form,legend="Modification Classe")


@app.route('/led/classe/del/<int:classe_id>',methods=['POST'])
@login_required
def del_classe(classe_id):                             
    classe=Classe.query.get_or_404(classe_id)
    if classe.supervisorClasse!= current_user:
        abort(404)
    eleves=Eleve.query.filter_by(classeDesEleves=classe).first()
    if eleves:
        flash('Vous ne pouvez pas supprimer cette classe car il ya des eleves qui y sont inscrits','warning')
        return redirect(url_for('index_classe'))
    else:
        db.session.delete(classe)
        db.session.commit()
        flash('La Classe a été supprimée','success')
        return redirect(url_for('index_classe'))

@app.route('/led/classe/search',methods=['GET','POST'])
def search_classe():
    form=SearchClasseForm()
    # classes=Classe.query.order_by(Classe.date_creation.desc()).paginate(page=page,per_page=5)
    if form.validate_on_submit():
        nom_classe=form.nomClasse.data.strip()
        # classes=Classe.query.filter(Classe.nom_classe.ilike('%'+ nom_classe+'%'))\
        #                       .order_by(Classe.date_creation.desc())\
        #                       .paginate(page=page,per_page=5)

        classes=Classe.query.filter(Classe.nom_classe.ilike('%'+ nom_classe+'%'))\
                              .order_by(Classe.date_creation.desc())                     
        
        # classes=Classe.query.filter(Classe.nom_classe.contains("%s" % nom_classe))\
        #                       .order_by(Classe.date_creation.desc())\
        #                       .paginate(page=page,per_page=5)
        if classes is None :
             flash('Cette Classe nest pas retrouvée','info')
             # return redirect(url_for('index_classe'))
        else:
            return render_template('classes/search_classe.html',classes=classes,form=form)
    else:
        return render_template('classes/search_classe.html',form=form)





################################  PARTIE  ElEVE  ##################################################################"


@app.route('/led/eleves')
def index_eleve():
    form=SearchEleveForm()
    page=request.args.get('page',1,type=int)
    # classes=Classe.query.all()
    eleves=Eleve.query.order_by(Eleve.date_inscription.desc()).paginate(page=page,per_page=5)
    return render_template('eleves/index_eleve.html',eleves=eleves, form=form)

@app.route('/led/new/eleve', methods=['GET', 'POST'])
@login_required
def new_eleve():
    
    form=AjoutEleveForm()
    errorprenom=''
    errornom=''
    erroremail=''
    errordate=''
    errortel=''
    patternprenom=re.compile('^[A-Z\s]+$',re.IGNORECASE)
    patterntel=re.compile('^7[0-8]([0-9]){7}')
    patterndate=re.compile('^[0-2][0-9]|3[0-1]/[0-1][0-2]/([0-9]){4}')
    patternemail=re.compile('^([\w\.-])+@([\w]+\.)+([a-zA-Z]){2,4}')

    
    if request.method == 'POST':
        prenom=form.prenom.data.strip()
        if patternprenom.match(prenom) is None:
            errorprenom='Prenom doit contenir que des lettres'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève",errorprenom=errorprenom)
        nom=form.nom.data.strip()
        if patternprenom.match(nom) is None:
            errornom='Nom doit contenir que des lettres'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève",errornom=errornom)
        email=form.email.data.strip()
        if patternemail.match(email) is None:
            erroremail='Donnez un bon format email'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève",erroremail=erroremail)
        dateNaissance=form.dateNaissance.data
        if dateNaissance:
            if patterndate.match(str(dateNaissance)) is None:
                errordate='Donnez un bon format date jj/mm/aaaa'
                form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
                form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
                return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Eleve",errordate=errordate)
        else:
            if patterndate.match(str(dateNaissance)) is None:
                errordate='Donnez un bon format date jj/mm/aaaa'
                form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
                form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
                return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève",errordate=errordate)
        tel=form.tel.data.strip()
        if patterntel.match(tel) is None:
            errortel='Telephone doit contenir que des chiffres format:77|78|70|76|'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève",errortel=errortel)
        adresse=form.adresse.data
        classeInscrit=form.classeInscrit.data
        annee_scolaire=form.annee_scolaire.data
        
        classe=Classe.query.filter_by(nom_classe=classeInscrit,annee_scolaire=annee_scolaire).first_or_404()

        eleve = Eleve(prenom=prenom,nom=nom,email=email,date_naissance=dateNaissance.strftime('%d/%m/%Y') ,num_telephone=tel,adresse=adresse,supervisorEleve=current_user,classeDesEleves=classe)
        db.session.add(eleve)
        db.session.commit()
        flash('Inscription de l\'élève réussie ', 'success')
        return  redirect(url_for('index_eleve'))
    elif request.method == 'GET': 
        form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.order_by(Classe.nom_classe.asc())]
        form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
        
    return render_template('eleves/new_eleve.html',title="Inscription Eleve",form=form,legend="Inscription Elève")

@app.route('/led/eleve/search', methods=['POST','GET'])
def search_eleve():
    form=SearchEleveForm()
    if form.validate_on_submit():
        prenomeleve=form.prenomeleve.data.strip()
        eleves=Eleve.query.filter(Eleve.prenom.ilike('%'+prenomeleve+'%'))\
                              .order_by(Eleve.date_inscription.desc())
        # classes=Classe.query.filter(Classe.nom_classe.contains("%s" % nom_classe))\
        #                       .order_by(Classe.date_creation.desc())\
        #                       .paginate(page=page,per_page=5)
        if eleves is None :
             flash('Cette Classe nest pas retrouvée','info')
             return redirect(url_for('search_eleve'))
        else:
            return render_template('eleves/search_eleve.html',eleves=eleves,form=form)
    else:
        return render_template('eleves/search_eleve.html',form=form)


        

@app.route("/led/eleve/classe/<string:nomClasse>/")
def eleve_classe(nomClasse):
    page=request.args.get('page',1,type=int)
    classe=Classe.query.filter_by(nom_classe=nomClasse).first_or_404()

    eleves=Eleve.query.filter_by(classeDesEleves=classe)\
                    .order_by(Eleve.date_inscription.desc())\
                    .paginate(page=page,per_page=5)
    return render_template('eleves/eleve_classe.html',eleves=eleves,classe=classe)


@app.route('/led/eleve/update/<int:eleve_id>',methods=['POST','GET'])
@login_required
def update_eleve(eleve_id):
    eleve=Eleve.query.get_or_404(eleve_id)
    errorprenom=''
    errornom=''
    erroremail=''
    errordate=''
    errortel=''
    patternprenom=re.compile('^[A-Z\s]+$',re.IGNORECASE)
    patterntel=re.compile('^7[0-8]([0-9]){7}')
    patterndate=re.compile('^[0-2][0-9]|3[0-1]/[0-1][0-2]/([0-9]){4}')
    patternemail=re.compile('^([\w\.-])+@([\w]+\.)+([a-zA-Z]){2,4}')

    if eleve.supervisorEleve!= current_user:
        abort(404)
    form=AjoutEleveForm(classeInscrit=eleve.classeDesEleves.nom_classe) 
    if request.method == 'POST':
        prenom = form.prenom.data.strip()
        if patternprenom.match(prenom) is None:
            errorprenom='Prenom doit contenir que des lettres'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Modifier Inscription",form=form,legend="Modification Inscription Eleve",errorprenom=errorprenom)
        nom = form.nom.data.strip()
        if patternprenom.match(nom) is None:
            errornom='Nom doit contenir que des lettres'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Modifier Eleve",form=form,legend="Modification Inscription Eleve",errornom=errornom)
        email = form.email.data.strip()
        if patternemail.match(email) is None:
            erroremail='Donnez un bon format email'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Modifier Eleve",form=form,legend="Modification Inscription  Eleve",erroremail=erroremail)
        dateNaissance = form.dateNaissance.data
        if dateNaissance:
            if patterndate.match(str(dateNaissance)) is None:
                errordate='Donnez un bon format date jj/mm/aaaa'
                form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
                form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
                return render_template('eleves/new_eleve.html',title="Modifier Eleve",form=form,legend="Modification Inscription Eleve",errordate=errordate)
        else:
            if patterndate.match(str(dateNaissance)) is None:
                errordate='Donnez un bon format date jj/mm/aaaa'
                form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
                form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
                return render_template('eleves/new_eleve.html',title="Modifier Eleve",form=form,legend="Modification Inscription Eleve",errordate=errordate)
        tel = form.tel.data.strip()
        if patterntel.match(tel) is None:
            errortel='Telephone doit contenir que 9 chiffres commençant par:77|78|70|76|'
            form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.all()]
            form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 
            return render_template('eleves/new_eleve.html',title="Modifier Eleve",form=form,legend="Modification Inscription Eleve",errortel=errortel)
        adresse = form.adresse.data
        classeInscrit = form.classeInscrit.data
        annee_scolaire = form.annee_scolaire.data

        classe=Classe.query.filter_by(nom_classe=classeInscrit,annee_scolaire=annee_scolaire).first_or_404()

        
        eleve.prenom = prenom
        eleve.nom = nom
        eleve.email = email
        eleve.date_naissance = dateNaissance.strftime('%d/%m/%Y')
        eleve.num_telephone = tel
        eleve.adresse = adresse
        eleve.supervisorEleve = current_user
        eleve.classeDesEleves = classe
        db.session.commit()
        flash('Inscription Elève a été modifiée','success')
        return redirect(url_for('index_eleve'))
    elif request.method =='GET':
        form.prenom.data = eleve.prenom
        form.nom.data = eleve.nom
        form.email.data=eleve.email
        form.dateNaissance.data=datetime.strptime(eleve.date_naissance,'%d/%m/%Y')
        form.tel.data=eleve.num_telephone
        form.adresse.data=eleve.adresse
        form.classeInscrit.choices=[(classe.nom_classe,classe.nom_classe) for classe in Classe.query.order_by(Classe.nom_classe.asc())]
        form.annee_scolaire.choices=[(classe.annee_scolaire,classe.annee_scolaire) for classe in Classe.query.with_entities(Classe.annee_scolaire).distinct()] 

    return render_template('eleves/new_eleve.html',title="Modifier Inscription",form=form,legend="Modification Inscription Eleve")


@app.route('/led/eleve/del/<int:eleve_id>',methods=['POST'])
@login_required
def del_eleve(eleve_id):                             
    eleve=Eleve.query.get_or_404(eleve_id)
    if eleve.supervisorEleve!= current_user:
        abort(404)
    
    db.session.delete(eleve)
    db.session.commit()
    flash('L\'Eleve a été supprimé','success')
    return redirect(url_for('index_eleve'))


@app.route('/led/eleve/show/<int:eleve_id>')
def show_eleve(eleve_id):                             
    eleve=Eleve.query.get_or_404(eleve_id)
    return render_template('eleves/show_eleve.html',eleve=eleve)

########################################      Partie main ########################################
@app.route("/home",methods = ["POST", "GET"])
def home():
    
    return render_template("pages/home.html")




###########################################   Partie Errors        ############################################################

@app.errorhandler(404)
def error_404(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def error_403(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(500)
def error_500(error):
    return render_template('errors/500.html'), 500
