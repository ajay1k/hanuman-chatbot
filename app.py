import os
import base64
from datetime import datetime
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
from PIL import Image
import io

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('89b4fcd0b3373dbd5782d7d1d0f70f6b')
GEMINI_API_KEY = os.environ.get('AIzaSyBcq8jfp8IievJB9bGsL3g6iMvnzhyzCYw')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions & Services ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Safely configure Gemini API
model = None
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        system_instruction = "You are a digital sevak inspired by Lord Hanuman..."
        model = genai.GenerativeModel(model_name="gemini-1.5-flash", system_instruction=system_instruction)
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
else:
    print("WARNING: GEMINI_API_KEY environment variable not found.")

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    messages = db.relationship('ChatMessage', backref='author', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_type = db.Column(db.String(10), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

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

# --- Main Routes ---
@app.route('/')
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
            return redirect(url_for('chat'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', title='Log In', form=form)

# ... (Register and Logout routes remain the same)
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
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Protected Routes ---
@app.route('/chalisa')
@login_required
def chalisa_player():
    return render_template('chalisa.html')

@app.route('/chat')
@login_required
def chat():
    past_messages = ChatMessage.query.filter_by(author=current_user).order_by(ChatMessage.timestamp).all()
    return render_template('chat.html', past_messages=past_messages)

# --- NEW: Gemini API Routes ---

@app.route('/get_prasad', methods=['POST'])
@login_required
def get_prasad():
    """Generates a spiritual thought for the day."""
    if not model:
        return jsonify({'response': 'Chatbot is not configured.'}), 500
    try:
        prompt = "In the persona of Hanuman's sevak, provide a short, one-sentence spiritual quote or 'thought for the day' based on Bhakti Yoga. Make it encouraging and easy to understand."
        response = model.generate_content(prompt)
        return jsonify({'response': response.text})
    except Exception as e:
        print(f"Error in get_prasad: {e}")
        return jsonify({'response': 'Sorry, an error occurred.'}), 500


@app.route('/identify_image', methods=['POST'])
@login_required
def identify_image():
    """Identifies an uploaded image."""
    if not model:
        return jsonify({'response': 'Chatbot is not configured for image analysis.'}), 500
    
    data = request.json
    image_data_url = data.get('image_data')

    if not image_data_url:
        return jsonify({'response': 'No image data received.'}), 400

    try:
        # Decode the Base64 image data
        header, encoded = image_data_url.split(",", 1)
        image_bytes = base64.b64decode(encoded)
        image = Image.open(io.BytesIO(image_bytes))

        prompt = "In the persona of Hanuman's sevak, please identify the deity or symbol in this image within the context of Hindu dharma. Describe its significance in one or two short sentences."
        
        # Make a multimodal request to the Gemini API
        response = model.generate_content([prompt, image])
        
        return jsonify({'response': response.text})
    except Exception as e:
        print(f"Error in identify_image: {e}")
        return jsonify({'response': 'Sorry, I could not analyze the image.'}), 500


@app.route('/get_chat_response', methods=['POST'])
@login_required
def get_chat_response():
    # This existing function is updated to use the same logic
    # It now saves messages to the database
    if not model:
        return jsonify({'response': 'Chatbot is not configured.'}), 500
    
    user_message_text = request.json['message']
    user_message_db = ChatMessage(sender_type='user', message_text=user_message_text, author=current_user)
    db.session.add(user_message_db)
    
    try:
        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(user_message_text)
        bot_response_text = response.text
        bot_message_db = ChatMessage(sender_type='bot', message_text=bot_response_text, author=current_user)
        db.session.add(bot_message_db)
        db.session.commit()
        return jsonify({'response': bot_response_text})
    except Exception as e:
        db.session.rollback()
        print(f"Error in get_chat_response: {e}")
        return jsonify({'response': 'Sorry, an error occurred.'}), 500

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
