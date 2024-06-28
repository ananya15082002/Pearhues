
class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # Example SQLite URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Optional, but recommended for performance

    SECRET_KEY = 'your_secret_key_here'  # Replace with a secure secret key
    GOOGLE_OAUTH_CLIENT_ID =''#replace with your
    GOOGLE_OAUTH_CLIENT_SECRET = ''#replace with your