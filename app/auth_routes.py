from flask import Blueprint, request, jsonify, current_app
from db import db
import jwt
import datetime

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

auth_bp = Blueprint('auth', __name__)

GOOGLE_CLIENT_ID = "708284276278-5jtdckcv1atn4ad46ogo4r5p1lh4g8l6.apps.googleusercontent.com"

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return {"error": "Missing fields"}, 400

    existing_user = db.users.find_one({"email": email})
    if existing_user:
        return {"error": "User already exists"}, 400

    user_data = {
        "username": username,
        "email": email,
        "password": password
    }
    db.users.insert_one(user_data)
    return {"message": "User created successfully"}, 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return {"error": "Missing fields"}, 400

    user = db.users.find_one({"email": email})
    if user and user['password'] == password:
        token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, current_app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})

    else:
        return {"error": "Invalid email or password"}, 401


@auth_bp.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return {"error": "Missing token"}, 400

    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        email = idinfo['email']
        username = idinfo.get('name', email.split('@')[0])

        user = db.users.find_one({"email": email})

        if not user:
            user_data = {
                "username": username,
                "email": email,
                "password": None
            }
            db.users.insert_one(user_data)

        jwt_token = jwt.encode({
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, current_app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token': jwt_token, 'email': email})

    except ValueError:
        return {"error": "Invalid Google token"}, 401
