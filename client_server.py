from flask import Flask, redirect, url_for, request, session, render_template, flash
import requests
import os
import secrets

app = Flask(__name__, template_folder="client/templates")
app.secret_key = os.urandom(24)

# Configuration
AUTHORIZATION_SERVER_BASE_URL = 'http://localhost:5000'
CLIENT_ID = 'client123'  # Ensure this matches the authorization server
CLIENT_SECRET = 'secret456'  # Ensure this matches the authorization server
REDIRECT_URI = 'http://localhost:8000/callback'
AUTHORIZATION_ENDPOINT = '/auth'
TOKEN_ENDPOINT = '/token'
PROTECTED_RESOURCE_ENDPOINT = '/protected_resource'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    # Generate a random state token for CSRF protection
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    auth_url = f"{AUTHORIZATION_SERVER_BASE_URL}{AUTHORIZATION_ENDPOINT}"
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'response_type': 'code'
    }
    request_url = requests.Request('GET', auth_url, params=params).prepare().url
    return redirect(request_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return 'Authorization code not found.', 400

    # Verify state parameter to prevent CSRF attacks
    if state != session.get('oauth_state'):
        return 'State mismatch. Possible CSRF attack.', 400

    session.pop('oauth_state', None)

    # Exchange the authorization code for an access token
    token_url = f"{AUTHORIZATION_SERVER_BASE_URL}{TOKEN_ENDPOINT}"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        token_info = response.json()
        access_token = token_info.get('access_token')
        session['access_token'] = access_token
        return redirect(url_for('profile'))
    else:
        error_description = response.json().get('error_description', 'Unknown error.')
        return f'Failed to obtain access token: {error_description}', 400

@app.route('/profile')
def profile():
    access_token = session.get('access_token')
    if not access_token:
        flash('Please log in first.')
        return redirect(url_for('login'))

    resource_url = f"{AUTHORIZATION_SERVER_BASE_URL}{PROTECTED_RESOURCE_ENDPOINT}"
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(resource_url, headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        username = user_info.get('username')
        return render_template('profile.html', username=username)
    else:
        # Clear invalid access token and redirect to login
        session.pop('access_token', None)
        flash('Session expired or invalid. Please log in again.')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(port=8000, debug=True)
