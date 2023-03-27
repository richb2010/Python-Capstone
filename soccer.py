from flask import Flask,redirect,url_for,render_template,request,session,flash, logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length
from flask_login import LoginManager, login_user, login_required, logout_user,login_url,current_user,UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os 
from flask_sqlalchemy import SQLAlchemy
import pandas
import pandas as pd
import pandas
import psycopg2
from flask_bootstrap import Bootstrap




app=Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
#app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/soccer data'




soccer_filename = "soccer.csv"


class RegisterForm(FlaskForm):
    username = StringField(name = "username", validators = [DataRequired(),Length(3,30)])
    password =  StringField(name = "username", validators = [DataRequired(),Length(3,30)])
    

class LoginForm(FlaskForm):
    username = StringField(name = 'Username', validators = [DataRequired(),Length(3,30)])
    password = StringField(name = 'Password', validators = [DataRequired(),Length(3,30)])
    submit = SubmitField('Sign In')


class Cards(FlaskForm):
    YellowCard = StringField(name = "YellowCard", validator = [DataRequired(), Length(5,50)])
    RedCard = StringField(name = "Red Card", validator = [DataRequired(), Length(5,50)])



soccer_filename = "soccer.csv"

dict_from_csv = pd.read_csv('soccer.csv', header=None, index_col=0, squeeze=True).to_dict()



db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




class Officials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.String(100),  nullable=False)
    pitch_id = db.Column(db.String(10), nullable=False)
    Home_name = db.Column(db.String(100), nullable=False)
    Away_name = db.Column(db.String(100), nullable=False)
    Home_Score = db.Column(db.String(3), nullable=False)
    Away_Score = db.Column(db.String(3), nullable=False)
    Center_official = db.Column(db.String(100), nullable=False)
    AR1_official = db.Column(db.String(100), nullable=False)
    AR2_official = db.Column(db.String(100), nullable=False)
    YellowCard = db.Column(db.String(100), nullable=False)
    RedCard = db.Column(db.String(100), nullable=False)

    created_at = db.Column(db.DateTime(timezone=True))

def get_officials():
     officials  = Officials.query.filter_by(user_id = current_user.id).all() #SELECT * FROM OFFICIALS
     return [o.officials for o in officials]

def add_Cards(a_card):
    c = Cards(YellowCard = a_card, user_id = current_user.id)
    c= Cards(RedCard = a_card, user_id = current_user.id)
    db.session.add(c)
    db.session.commit()

def get_Cards():
    Cards = Cards.query.filter_by(YellowCard =current_user.id) #SELECT * FROM CARDS
    return [c.cards for c in Cards]

class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password = db.Column(db.String(80))

 
@login_manager.user_loader
def loader_user(user_id):
   return user.get(user_id)
app=Flask(__name__)
@app.route("/", methods=['GET', 'POST'])
def home():
	""" Session control"""
	if not session.get('logged_in'):
		return render_template('home.html')
	else:
		if request.method == 'POST':

			return redirect('home.html') 
		return render_template('index.html')

@app.route("/login", methods =['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.user_name.data == 'admin' and form.password.data == 'admin':
            flash('login successful')
            return redirect('index')
    return render_template('login.html', form=form)


@app.route("/register", methods=['POST', 'GET'])
def register():
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
        db.session.add(register)
        db.session.commit()

        return redirect('login.html')
    return render_template('register.html')
@app.route("/dashboard", methods=['POST', 'GET'])
def dashboard():
     if request.method == 'POST':
          title = request.form['Soccer Games']
          content = request.form['content']

          if not title: 
               flash('Title is required!')
          elif not content:
               flash('content is DataRequired!')
          else: 
               message.append({'Soccer Game': title, 'content': content})
               return redirect(url_for('index'))
     return render_template('dashboard.html')
@app.route("/logout")
def logout():
     session.pop('user, None')
     return redirect("/")
     



     
   

@app.route("/card")
def card():
    return render_template('card.html')

@app.route("/cards", methods = ['POST', 'GET'])
def cards():
    if request.methods == "POST":
        result = request.form
        return render_template("cards.html")        
            
if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run(port=5000,debug=True)