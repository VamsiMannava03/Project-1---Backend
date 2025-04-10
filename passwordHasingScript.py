"""
    This script is used to manually generate a password has to store in the mysql database.
    To use:
        1. Install Flask-Bcrypt: pip install Flask-Bcrypt
        2. Run this script: python passwordHasingScript.py
        3. Copy the generated hash.
        4. When creating the user, use the generated hash as the password.
"""
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()
print(bcrypt.generate_password_hash('admin123').decode('utf-8'))
