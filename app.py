from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager
from datetime import timedelta

## Configurations ##
login_manager = LoginManager()

app = Flask(__name__)

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Eyad1582005@127.0.0.1/auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(minutes=5)

db = SQLAlchemy(app)
Migrate(app,db)

login_manager.init_app(app)
login_manager.login_view = 'login'


## Create Model ##
bcrypt = Bcrypt()

@login_manager.user_loader
def user_load(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):

    __tablename__ = "User"

    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    hash_password = db.Column(db.String(128), nullable=False)

    def __init__(self, email, username, password):

        self.email = email
        self.username = username
        self.hash_password = bcrypt.generate_password_hash(password=password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.hash_password, password=password)


## Forms ##
class Login_form(FlaskForm):

    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remebmber Me")
    submit = SubmitField("Submit")

class Registration_form(FlaskForm):

    email = EmailField("Email", validators=[DataRequired(), Email()])
    username = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo("pass_confirm", message="Passwords have to match")])
    pass_confirm = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def check_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Your email already exists")
        
    def check_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Your username already exsits")


## Routes ##
@app.route('/')
def index():
    return render_template('home.html')


@app.route('/welcome')
@login_required
def welcome_user():
    return render_template('welcome_user.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You logged out!")
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():

    form = Registration_form()
    if form.validate_on_submit():

        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Thanks for signing up!")

        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():

    form = Login_form()
    if form.validate_on_submit():

        user = User.query.filter_by(email=form.email.data).first()

        if user.check_password(form.password.data) is not None:
            login_user(user, remember=form.remember.data)
            flash("You've successfully loged in!")

            next = request.args.get('next')
            if next == None or not next[0] == '/':
               next = url_for('welcome_user')

            return redirect(next)
    return render_template('login.html', form=form)


    
        


