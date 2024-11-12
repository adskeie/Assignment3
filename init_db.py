import sqlite3
import logging

DATABASE = 'app.db'

def init_db():
    """Initialize the database and create tables if they do not exist."""
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            totp_secret TEXT,
            failed_attempts INTEGER DEFAULT 0,
            last_failed_attempt DATETIME
        );
    ''')
    # Create OAuthClients table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS OAuthClients (
            client_id TEXT PRIMARY KEY,
            client_secret TEXT NOT NULL,
            redirect_uri TEXT NOT NULL
        );
    ''')
    # Create OAuthCodes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS OAuthCodes (
            code TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES Users(id)
        );
    ''')
    # Create OAuthTokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS OAuthTokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES Users(id)
        );
    ''')
    db.commit()
    db.close()
    logging.info("Database initialized and tables created.")
