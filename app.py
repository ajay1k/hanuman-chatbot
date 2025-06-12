import os
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai

# --- App Configuration ---
app = Flask(__name__)

# --- CHANGED SECTION: Keys are now loaded securely from the environment ---
# This is the most important change for security before uploading to GitHub.
app.config['SECRET_KEY'] = os.environ.get('88238f843bfb5a4c1ba55c69591de6b1')
GEMINI_API_KEY = os.environ.get('AIzaSyBcq8jfp8IievJB9bGsL3g6iMvnzhyzCYw')
# ----------------------------------------------------------------------

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions & Services ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# We must configure the Gemini API, but we'll do it safely.
# This 'if' statement prevents the app from crashing if the key isn't set yet on your local machine.
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("Warning: GEMINI_API_KEY not found. Chatbot functionality will be limited.")

system_instruction = "You are a digital sevak inspired by Lord Hanuman..." # Shortened for brevity
model = genai.GenerativeModel(model_name="gemini-1.5-flash", system_instruction=system_instruction)


# --- Database Model & User Loader ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Web Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('That username is already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')


# --- Routes ---
@app.route('/')
@app.route('/home')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('chat'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('chat'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', title='Log In', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('chat'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- PROTECTED CHATBOT ROUTES ---
@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/get_chat_response', methods=['POST'])
@login_required
def get_chat_response():
    if not GEMINI_API_KEY:
        return jsonify({'response': 'The chatbot is not configured on the server. Please contact the administrator.'}), 500
    try:
        user_message = request.json['message']
        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(user_message)
        return jsonify({'response': response.text})
    except Exception as e:
        print(f"Error in get_chat_response: {e}")
        return jsonify({'response': 'Sorry, an error occurred.'}), 500

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)