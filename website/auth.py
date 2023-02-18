from flask import Blueprint,render_template,request,flash,redirect,url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,login_required,logout_user,current_user

auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email= email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                flash('Logged in Successfully', category= 'success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again', category= 'error')
        else:
            flash('Email does not exist', category= 'error')

    return render_template('login.html', user = current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up',methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstname')
        second_name = request.form.get('secondname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email= email).first()
        if user:
            flash('Email already exist', category='error')
        elif len(email) < 4:
            flash('Enter valid email id',category='error')
        elif len(first_name) < 2:
            flash('FirstName is too Short',category='error')
        elif len(second_name) < 2:
            flash('SecondName is too Short',category='error')
        elif password1 != password2:
            flash('Passwords don\'t matched',category='error')
        elif len(password1) < 7:
            flash('Password length must be 7 or more',category='error')
        else:
            new_user = User(email= email, first_name= first_name, second_name= second_name,password=generate_password_hash(password1,method='sha256') )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account Created Successfully',category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html', user = current_user)
