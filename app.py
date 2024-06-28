import os

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_dance.contrib.google import google, make_google_blueprint
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from models import User, db

# Ensure HTTPS is not enforced during development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    redirect_to='google_login',
    scope=["https://www.googleapis.com/auth/userinfo.profile", "openid", "https://www.googleapis.com/auth/userinfo.email"]
)
app.register_blueprint(google_bp, url_prefix='/login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return render_template('message.html', message='You are already logged in.')
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return render_template('message.html', message='You are already logged in.')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please log in.', 'info')
            return redirect(url_for('login'))
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Account created successfully!', 'success')
            return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    
    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
    if not resp.ok:
        flash('Failed to fetch user info from Google.', 'danger')
        return redirect(url_for('login'))

    user_info = resp.json()
    email = user_info.get('email')
    if email is None:
        flash('Could not get email from Google.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        # Create a new user if not already registered
        user = User(email=email, password=generate_password_hash("", method='sha256'))
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
