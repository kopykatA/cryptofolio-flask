from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin
from functools import wraps
from .utils.auth import generate_token, requires_auth, verify_token
from flask import request, render_template, jsonify, url_for, redirect, g
from index import app, db
from sqlalchemy.exc import IntegrityError
from .models import User
from index import  bcrypt
import pyrebase


config = {
  'apiKey': "AIzaSyBAdbuh9uT22E-eV9tGJRW3tUOksPI-DuA",
  'authDomain': "cryptofolio-63e51.firebaseapp.com",
  'databaseURL': "https://cryptofolio-63e51.firebaseio.com",
  'projectId': "cryptofolio-63e51",
  'storageBucket': "cryptofolio-63e51.appspot.com",
  'messagingSenderId': "1043732935820",
  "serviceAccount": "application/utils/cryptofolio-63e51-firebase-adminsdk-qyyy2-45e3a5a728.json"
}

firebase = pyrebase.initialize_app(config)
# Get a reference to the database service
db = firebase.database()

CORS(app, support_credentials=True)

@cross_origin(supports_credentials=True)
def redirect_to_signin():
    status = False
    return jsonify({'result': status})

def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message="Invalid email"), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/register', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def register():
    request_json = request.get_json()
    data = request_json['data']
    email = data['email']
    password = data['password']
    try:
        all_users = db.child("users").get()
        for user in all_users.each():
            user_val = user.val()
            user_email = user_val['email']
            if user_email == email:
                raise Exception('user already registered')
        db.child("users").push(data)
    except Exception as error:
        print error
    return 'OK'

@app.route('/login', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    request_json = request.get_json()
    data = request_json['data']
    email = data['email']
    password = data['password']
    try:
        all_users = db.child("users").get()
        for user in all_users.each():
            user_val = user.val()
            user_email = user_val['email']
            user_password = user_val['password']
            if user_email == email and user_password == password:
                verified_user = {
                    'email': user_email,
                    'password': user_password,

                }
                return jsonify(token=generate_token(verified_user))
            else:
                return jsonify(error=True), 403
    except Exception as error:
        print error
    return 'OK'
    # request_json = request.get_json()
    # data = request_json['data']
    # email = data['email']
    # password = data['password']
    # user = User.get_user_with_email_and_password(email, password)
    # if user:
    #     return jsonify(token=generate_token(user))
    #
    # return jsonify(error=True), 403
    #
    # request_json = request.get_json()
    # data = request_json['data']
    # email = data['email']
    # password = data['password']
    #
    # user = User.query.filter_by(email=email).first()
    # status = False
    # if user:
    #     if user.password == password:
    #         login_user(user)
    #         print 'logged in'
    #         status = True
    #         return jsonify(token=generate_token(user))
    #     else:
    #         print 'cant log in'
    # return jsonify({'result': status})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>' + 'New user has been created' + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=['GET', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def dashboard():
    status = True
    return jsonify({'result': status})

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
