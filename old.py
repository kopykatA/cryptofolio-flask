from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import jsonify
from flask_cors import CORS, cross_origin
from flask import g, request
from functools import wraps
from utils.auth import generate_token, requires_auth, verify_token

app = Flask(__name__)
CORS(app, support_credentials=True)

app.config['SECRET_KEY'] = 'This is secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/zy/Desktop/Files/projects/flaskapp/database.db'

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

# @login_manager.unauthorized_handler
# def unauthorized():
#     # do stuff
#     status = False
#     return jsonify({'result': status})

@login_manager.unauthorized_handler
@cross_origin(supports_credentials=True)
def redirect_to_signin():
    status = False
    return jsonify({'result': status})

@login_manager.user_loader
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
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        db.session.close()
        status = 'success'
    except:
        status = 'this user is already registered'
    return 'OK'

@app.route('/login', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True)
def login():
    request_json = request.get_json()
    data = request_json['data']
    email = data['email']
    password = data['password']

    user = User.query.filter_by(email=email).first()
    status = False
    if user:
        if user.password == password:
            login_user(user)
            print 'logged in'
            status = True
            return jsonify(token=generate_token(user))
        else:
            print 'cant log in'
    return jsonify({'result': status})

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
@login_required
def dashboard():
    status = True
    return jsonify({'result': status})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
