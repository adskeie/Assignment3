from flask import (
    Flask, request, render_template, redirect, url_for, session,
    g, jsonify, flash
)
import sqlite3
import os
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta
import uuid
from functools import wraps
import logging
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
)

# Set session cookie security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

DATABASE = 'app.db'
LOCKOUT_TIME = timedelta(minutes=5)
CLIENT_ID = "client123"
CLIENT_SECRET = "secret456"
REDIRECT_URI = 'http://localhost:8000/callback'

def get_db():
    """Get a database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        # Connect to the SQLite database
        db = g._database = sqlite3.connect(DATABASE)
        # Enable foreign key support
        db.execute('PRAGMA foreign_keys = ON;')
        # Return rows as dictionaries
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Initialize OAuth clients
def init_oauth_clients():
    """Initialize OAuth clients in the database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM OAuthClients WHERE client_id = ?', (CLIENT_ID,))
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO OAuthClients (client_id, client_secret, redirect_uri)
            VALUES (?, ?, ?)
        ''', (CLIENT_ID, CLIENT_SECRET, REDIRECT_URI))
        db.commit()
    else:
        # Update redirect_uri if it has changed
        cursor.execute('''
            UPDATE OAuthClients SET client_secret = ?, redirect_uri = ? WHERE client_id = ?
        ''', (CLIENT_SECRET, REDIRECT_URI, CLIENT_ID))
        db.commit()

def login_required(f):
    """Decorator to require login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.DataRequired()
    ])
    password = PasswordField('Password', [
        validators.Length(min=6),
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Repeat Password')

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

class TwoFactorForm(FlaskForm):
    totp_code = StringField('TOTP Code', [
        validators.DataRequired(),
        validators.Length(min=6, max=6, message='Enter a 6-digit code.')
    ])

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data.strip()
        password = form.password.data.strip()
        # Hash the password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        db = get_db()
        cursor = db.cursor()
        try:
            # Insert new user into Users table
            cursor.execute('''
                INSERT INTO Users (username, password_hash)
                VALUES (?, ?)
            ''', (username, password_hash))
            db.commit()
            user_id = cursor.lastrowid
            # Generate TOTP secret
            totp_secret = pyotp.random_base32()
            cursor.execute('''
                UPDATE Users SET totp_secret = ? WHERE id = ?
            ''', (totp_secret, user_id))
            db.commit()
            # Generate QR code
            otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=username, issuer_name="MyApp"
            )
            img = qrcode.make(otp_uri)
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            qr_code_img = base64.b64encode(buffer.getvalue()).decode('utf-8')
            flash("Registration successful. Set up two-factor authentication.")
            return render_template('show_qr.html', qr_code_img=qr_code_img)
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            logging.warning(f"Attempted registration with existing username: {username}")
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)

# Login Route with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data.strip()
        password = form.password.data.strip()
        db = get_db()
        cursor = db.cursor()
        # Fetch user by username
        cursor.execute('SELECT * FROM Users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            user_id = user['id']
            password_hash = user['password_hash']
            failed_attempts = user['failed_attempts']
            last_failed_attempt = user['last_failed_attempt']
            # Check for lockout
            if failed_attempts >= 3:
                if last_failed_attempt:
                    last_attempt_time = datetime.strptime(last_failed_attempt, '%Y-%m-%d %H:%M:%S.%f')
                    if datetime.utcnow() - last_attempt_time < LOCKOUT_TIME:
                        flash("Account locked due to multiple failed login attempts. Please try again later.")
                        logging.warning(f"Account locked for user: {username}")
                        return render_template('login.html', form=form)
                    else:
                        # Reset failed attempts after lockout period
                        cursor.execute('UPDATE Users SET failed_attempts = 0 WHERE id = ?', (user_id,))
                        db.commit()
                else:
                    # Handle case where last_failed_attempt is None
                    cursor.execute('UPDATE Users SET failed_attempts = 0 WHERE id = ?', (user_id,))
                    db.commit()
            # Verify password
            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                # Reset failed attempts on successful login
                cursor.execute('UPDATE Users SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = ?', (user_id,))
                db.commit()
                session['user_id'] = user_id
                flash("Login successful. Please complete two-factor authentication.")
                # Proceed to 2FA
                return redirect(url_for('two_factor_auth'))
            else:
                # Increment failed attempts
                failed_attempts += 1
                cursor.execute('''
                    UPDATE Users SET failed_attempts = ?, last_failed_attempt = ?
                    WHERE id = ?
                ''', (failed_attempts, datetime.utcnow(), user_id))
                db.commit()
                flash("Invalid credentials.")
                logging.warning(f"Invalid login attempt for user: {username}")
        else:
            flash("Invalid credentials.")
            logging.warning(f"Invalid login attempt with non-existing username: {username}")
    return render_template('login.html', form=form)

# Two-Factor Authentication Route
@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    form = TwoFactorForm(request.form)
    if request.method == 'POST' and form.validate():
        totp_code = form.totp_code.data.strip()
        user_id = session['user_id']
        db = get_db()
        cursor = db.cursor()
        # Fetch TOTP secret
        cursor.execute('SELECT totp_secret FROM Users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        if result:
            totp_secret = result['totp_secret']
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                # Successful login
                session['authenticated'] = True
                flash("Two-factor authentication successful.")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid TOTP code.")
                logging.warning(f"Invalid TOTP code for user ID: {user_id}")
        else:
            flash("User not found.")
            logging.error(f"TOTP secret not found for user ID: {user_id}")
    return render_template('two_factor_auth.html', form=form)

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('authenticated'):
        flash("Please complete two-factor authentication.")
        return redirect(url_for('two_factor_auth'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT username FROM Users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    return render_template('dashboard.html', username=user['username'])

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('index'))

# OAuth2 Authorization Endpoint
@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == 'GET':
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state')
        db = get_db()
        cursor = db.cursor()
        # Validate client_id and redirect_uri
        cursor.execute('SELECT * FROM OAuthClients WHERE client_id = ? AND redirect_uri = ?', (client_id, redirect_uri))
        client = cursor.fetchone()
        if client:
            session['client_id'] = client_id
            session['redirect_uri'] = redirect_uri
            session['state'] = state
            # Check if user is logged in and authenticated
            if 'user_id' in session and session.get('authenticated'):
                # User is already logged in and authenticated, ask for authorization
                return render_template('authorize.html', client_id=client_id)
            else:
                # Redirect to login
                flash("Please log in to authorize the application.")
                next_url = url_for('auth', client_id=client_id, redirect_uri=redirect_uri, state=state)
                return redirect(url_for('login', next=next_url))
        else:
            flash("Invalid client.")
            logging.warning(f"Invalid OAuth client_id: {client_id}")
            return render_template('error.html', message="Invalid client.")
    elif request.method == 'POST':
        # User approves authorization
        client_id = session.get('client_id')
        redirect_uri = session.get('redirect_uri')
        state = session.get('state')
        user_id = session.get('user_id')
        if not user_id:
            flash("Please log in to authorize the application.")
            return redirect(url_for('login'))
        # Generate authorization code
        auth_code = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO OAuthCodes (code, user_id, expires_at)
            VALUES (?, ?, ?)
        ''', (auth_code, user_id, expires_at))
        db.commit()
        # Redirect back to client
        return redirect(f"{redirect_uri}?code={auth_code}&state={state}")

# OAuth2 Token Endpoint
@csrf.exempt  # Exempt CSRF protection for API endpoint
@app.route("/token", methods=["POST"])
def token():
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_uri = request.form.get('redirect_uri')
    db = get_db()
    cursor = db.cursor()
    # Validate client credentials
    cursor.execute('''
        SELECT * FROM OAuthClients WHERE client_id = ? AND client_secret = ? AND redirect_uri = ?
    ''', (client_id, client_secret, redirect_uri))
    client = cursor.fetchone()
    if client:
        # Validate authorization code
        cursor.execute('SELECT * FROM OAuthCodes WHERE code = ?', (code,))
        auth_code = cursor.fetchone()
        if auth_code:
            user_id = auth_code['user_id']
            expires_at = datetime.strptime(auth_code['expires_at'], '%Y-%m-%d %H:%M:%S.%f')
            if expires_at > datetime.utcnow():
                # Invalidate the authorization code after use
                cursor.execute('DELETE FROM OAuthCodes WHERE code = ?', (code,))
                db.commit()
                # Generate access token
                access_token = str(uuid.uuid4())
                token_expires_at = datetime.utcnow() + timedelta(hours=1)
                cursor.execute('''
                    INSERT INTO OAuthTokens (token, user_id, expires_at)
                    VALUES (?, ?, ?)
                ''', (access_token, user_id, token_expires_at))
                db.commit()
                logging.info(f"Issued access token for user ID: {user_id}")
                return jsonify({'access_token': access_token, 'token_type': 'Bearer', 'expires_in': 3600})
            else:
                logging.warning("Authorization code expired.")
                return jsonify({'error': 'invalid_grant', 'error_description': 'Authorization code expired.'}), 400
        else:
            logging.warning("Invalid authorization code.")
            return jsonify({'error': 'invalid_grant', 'error_description': 'Invalid authorization code.'}), 400
    else:
        logging.warning("Invalid client credentials.")
        return jsonify({'error': 'invalid_client'}), 400

# Protected Resource Endpoint
@app.route("/protected_resource", methods=["GET"])
@limiter.limit("10 per minute")
def protected_resource():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        access_token = auth_header.split(' ')[1]
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM OAuthTokens WHERE token = ?', (access_token,))
        token = cursor.fetchone()
        if token:
            user_id = token['user_id']
            expires_at = datetime.strptime(token['expires_at'], '%Y-%m-%d %H:%M:%S.%f')
            if expires_at > datetime.utcnow():
                cursor.execute('SELECT username FROM Users WHERE id = ?', (user_id,))
                user = cursor.fetchone()
                if user:
                    username = user['username']
                    return jsonify({'username': username})
            logging.warning("Access token expired.")
            return jsonify({'error': 'invalid_token', 'error_description': 'Access token expired.'}), 401
        logging.warning("Invalid access token.")
        return jsonify({'error': 'invalid_token', 'error_description': 'Invalid access token.'}), 401
    logging.warning("Authorization header missing or malformed.")
    return jsonify({'error': 'invalid_request', 'error_description': 'Authorization header missing or malformed.'}), 400

# Error Handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found."), 404

if __name__ == '__main__':
    # Initialize database and OAuth clients
    from init_db import init_db
    init_db()
    with app.app_context():
        init_oauth_clients()
    app.run(debug=True)
