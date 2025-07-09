import sys
import os
import json
from datetime import datetime, timedelta
import random
import bcrypt
import jwt
import torch
import razorpay
import mimetypes
import time
import smtplib
from urllib.parse import unquote
from flask import send_from_directory, abort
from functools import wraps
from flask import Flask, request, jsonify
from flask import make_response
from flask_cors import CORS, cross_origin
from dotenv import load_dotenv
from bson.objectid import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient
from werkzeug.utils import secure_filename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage


# Load environment variables
load_dotenv()

# Razorpay client
razorpay_client = razorpay.Client(
    auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET"))
)

# OTP store with expiry
otp_store = {}  # { email: { otp: "123456", expiry: 1710000000 } }


style_data = {}
categories = ['men', 'women', 'boys', 'girls', 'kids']

for cat in categories:
    file_path = os.path.join('app', 'style_data', f'{cat}.json')
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            style_data[cat] = json.load(f)




app = Flask(__name__)

# ✅ CORS Setup
CORS(
    app,
    origins=["http://localhost:5173", "http://127.0.0.1:5173" , "http://<your-ip>:5173"],
    methods=["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-User-Email"],
    supports_credentials=True  # important if cookies or auth headers involved
)



@app.route('/admin/<path:path>', methods=['OPTIONS'])
def cors_preflight(path):
    response = app.make_default_options_response()
    return add_cors_headers(response)


# 🔐 Secret Key
app.config['SECRET_KEY'] = 'swadhinsecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'products')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB


@app.route('/static/uploads/products/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# 🗃️ MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["swadhinDB"]
db.testimonials.update_many({}, { "$set": { "visible": True } })

# 📦 Collections
users_col = db['users']
suggestions_col = db['user_suggestions']
products_col = db['products']
orders_col = db['orders']
lookbook_collection = db["lookbook"]
product_reviews_collection = db["product_reviews"]
coupon_collection = db['coupons']
gallery_collection = db['gallery_tiles']
banner_collection = db['banners']
notification_collection = db['notifications']
# 👑 Admin Email
ALLOWED_USER_EMAIL = "admin@example.com"
#baneer relted working routes............................................................................................
# 📂 Create new folder if not exist

BANNER_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'banners')
os.makedirs(BANNER_UPLOAD_FOLDER, exist_ok=True)



# 🔐 Admin Email Check
def is_admin():
    return request.headers.get('X-User-Email') == ALLOWED_USER_EMAIL

# ✅ Notifications
# ✅ Banners......................................................................................
@app.route('/static/uploads/hero/<path:filename>')
def serve_hero_file(filename):
    filename = unquote(filename)

    # 👉 ABSOLUTE path to your hero folder
    hero_folder = r"C:\Users\meetm\OneDrive\Desktop\SWADHIN\swadhin-backend\static\uploads\hero"

    file_path = os.path.join(hero_folder, filename)

    if not os.path.isfile(file_path):
        print(f"🛑 Not Found: {file_path}")
        return abort(404)

    return send_from_directory(hero_folder, filename)


# Upload hero banner (image/video)
@app.route('/upload/hero', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def upload_hero_file():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400

    filename = secure_filename(file.filename)
    upload_folder = "static/uploads/hero"
    os.makedirs(upload_folder, exist_ok=True)
    upload_path = os.path.join(upload_folder, filename)
    file.save(upload_path)

    # Return full URL so React can access it
    return jsonify({
        "fileUrl": f"http://localhost:5000/static/uploads/hero/{filename}"
    }), 200

# Add a hero slide
@app.route('/admin/hero-slide', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def add_hero_slide():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    required_fields = ['type', 'src', 'text', 'subtitle', 'overlayColor']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'{field} is required'}), 400

    if data['type'] not in ['image', 'video']:
        return jsonify({'error': 'Invalid type (must be image or video)'}), 400

    # 💡 Fix src if it’s not a full URL
    src = data['src']
    if not src.startswith("http"):
        host = request.host_url.rstrip('/')
        src = f"{host}{src.lstrip('/')}"

    new_slide = {
        "type": data['type'],
        "src": src,
        "text": data['text'],
        "subtitle": data['subtitle'],
        "overlayColor": data['overlayColor'],
        "created_at": datetime.utcnow()
    }

    try:
        db.hero_slides.insert_one(new_slide)
        return jsonify({"message": "Slide added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Get all hero slides
@app.route('/hero-slides', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_hero_slides():
    try:
        slides = list(db.hero_slides.find().sort("created_at", -1))
        for s in slides:
            s['_id'] = str(s['_id'])
        return jsonify({"slides": slides}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
#get all banners for all banner at admin side...............................................
@app.route('/admin/hero-slide', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_all_hero_slides():
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        slides = list(db.hero_slides.find().sort("created_at", -1))
        for slide in slides:
            slide["_id"] = str(slide["_id"])
        return jsonify({"slides": slides}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/hero-slide/<string:slide_id>', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def delete_hero_slide(slide_id):
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        result = db.hero_slides.delete_one({"_id": ObjectId(slide_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "Slide not found"}), 404
        return jsonify({"message": "Slide deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
#gllery section milestone ke niche vala ....................................................
@app.route('/upload/gallery', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def upload_gallery_file():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file provided"}), 400

    filename = secure_filename(file.filename)
    upload_folder = os.path.abspath("static/uploads/gallery")
    os.makedirs(upload_folder, exist_ok=True)
    upload_path = os.path.join(upload_folder, filename)
    file.save(upload_path)

    return jsonify({
        "fileUrl": f"http://localhost:5000/static/uploads/gallery/{filename}"
    }), 200

# 🔓 Serve uploaded gallery file
@app.route('/static/uploads/gallery/<path:filename>')
def serve_gallery_file(filename):
    filename = unquote(filename)
    gallery_folder = os.path.abspath("static/uploads/gallery")
    file_path = os.path.join(gallery_folder, filename)
    if not os.path.isfile(file_path):
        print(f"🛑 Not Found: {file_path}")
        return abort(404)
    return send_from_directory(gallery_folder, filename)

# 🔐 Admin: Add a new gallery tile
@app.route('/admin/gallery', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def add_gallery_tile():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    required = ['type', 'src', 'caption']
    if not all(data.get(field) for field in required):
        return jsonify({"error": "All fields are required"}), 400

    if data['type'] not in ['image', 'video']:
        return jsonify({"error": "Invalid type"}), 400

    tile = {
        "type": data['type'],
        "src": data['src'],
        "caption": data['caption'].strip(),
        "created_at": datetime.utcnow()
    }

    try:
        gallery_collection.insert_one(tile)
        return jsonify({"message": "Tile added"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔓 Public: Get all gallery tiles
@app.route('/gallery', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_public_gallery():
    try:
        tiles = list(gallery_collection.find().sort("created_at", -1))
        for t in tiles:
            t['_id'] = str(t['_id'])
        return jsonify({"tiles": tiles}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔐 Admin: Get all gallery tiles
@app.route('/admin/gallery', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_admin_gallery():
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        tiles = list(gallery_collection.find().sort("created_at", -1))
        for t in tiles:
            t['_id'] = str(t['_id'])
        return jsonify({"tiles": tiles}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔐 Delete gallery tile
@app.route('/admin/gallery/<string:tile_id>', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def delete_gallery_tile(tile_id):
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        result = gallery_collection.delete_one({"_id": ObjectId(tile_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "Tile not found"}), 404
        return jsonify({"message": "Tile deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500   
#milestone relted routes...................................................................
@app.route('/admin/testimonial', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def add_testimonial():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    required_fields = ['quote', 'author']
    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return jsonify({"error": f"{field} is required"}), 400

    new_testimonial = {
        "quote": data['quote'].strip(),
        "author": data['author'].strip(),
        "location": data.get('location', '').strip(),
        "caption": data.get('caption', '').strip(),
        "type": data.get('type', 'image').strip(),  # image or video
        "src": data.get('src', '').strip(),         # optional media
        "visible": data.get('visible', True),
        "created_at": datetime.utcnow()
    }

    try:
        db.testimonials.insert_one(new_testimonial)
        return jsonify({"message": "Testimonial added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔐 Get all testimonials (admin)
@app.route('/admin/testimonial', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_all_testimonials():
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        testimonials = list(db.testimonials.find().sort("created_at", -1))
        for t in testimonials:
            t['_id'] = str(t['_id'])
        return jsonify({"testimonials": testimonials}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔐 Delete testimonial by ID (admin)
@app.route('/admin/testimonial/<string:testimonial_id>', methods=['DELETE'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def delete_testimonial(testimonial_id):
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        result = db.testimonials.delete_one({"_id": ObjectId(testimonial_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "Testimonial not found"}), 404
        return jsonify({"message": "Testimonial deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔓 Public: Get only visible testimonials
@app.route('/testimonials', methods=['GET'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def get_visible_testimonials():
    try:
        testimonials = list(db.testimonials.find({"visible": True}).sort("created_at", -1))
        for t in testimonials:
            t['_id'] = str(t['_id'])
        return jsonify({"testimonials": testimonials}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# 🛠️ Utility Functions.......................................................................
def load_json(filename):
    with open(f'data/{filename}', 'r', encoding='utf-8') as file:
        return json.load(file)
    
def create_token(email):
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# ✅ Basic Route
@app.route('/')
def home():
    return 'Hello SWADHIN! Backend is running ✅'

def send_otp_email(recipient_email, otp):
    EMAIL_ID = os.getenv("EMAIL_ID")
    EMAIL_PASS = os.getenv("EMAIL_PASS")

    msg = EmailMessage()
    msg['Subject'] = 'Your SWADHIN Login OTP'
    msg['From'] = EMAIL_ID
    msg['To'] = recipient_email
    msg.set_content(f"Hello,\n\nYour OTP for SWADHIN login is: {otp}\nIt is valid for 5 minutes.")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ID, EMAIL_PASS)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Email send error:", str(e))
        return False

# 🔐 Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    if not email or not password or not username:
        return jsonify({'error': 'Missing email, password, or username'}), 400

    # 🔐 Allow only trusted domains + admin
    TRUSTED_DOMAINS = ["gmail.com", "yahoo.com", "apple.com", "outlook.com", "hotmail.com"]
    email_domain = email.split('@')[-1]
    if email != ALLOWED_USER_EMAIL and email_domain not in TRUSTED_DOMAINS:
        return jsonify({'error': 'Only trusted email domains are allowed'}), 400

    if users_col.find_one({'email': email}):
        return jsonify({'error': 'Email already registered'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_col.insert_one({'email': email, 'username': username, 'password': hashed_pw})

    token = create_token(email)
    return jsonify({'token': token, 'email': email})

# 🔐 Login Route
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Invalid JSON format'}), 400

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        user = users_col.find_one({'email': email})
        if not user or 'password' not in user:
            return jsonify({'error': 'Invalid email or password'}), 400

        stored_pw = user['password']
        if isinstance(stored_pw, str):
            stored_pw = stored_pw.encode('utf-8')

        if not bcrypt.checkpw(password.encode('utf-8'), stored_pw):
            return jsonify({'error': 'Invalid email or password'}), 400

        token = create_token(email)
        return jsonify({'token': token, 'email': email, 'isAdmin': email == ALLOWED_USER_EMAIL})

    except Exception as e:
        print("Login error:", str(e))
        return jsonify({'error': 'Internal server error'}), 500

# 🔐 Forgot Password
@app.route('/forgot-password', methods=['POST'])
@cross_origin()
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')

        user = users_col.find_one({'email': email})
        if not user:
            return jsonify({'error': 'Email not found'}), 404

        otp = str(random.randint(100000, 999999))
        expiry_time = time.time() + 300
        otp_store[email] = {'otp': otp, 'expiry': expiry_time}

        print(f"Sending OTP {otp} to {email}")

        sender_email = os.getenv("EMAIL_USER")
        sender_pass = os.getenv("EMAIL_PASS")

        if not sender_email or not sender_pass:
            return jsonify({'error': 'Email credentials not set'}), 500

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = 'Your SWADHIN Password Reset OTP'
        msg.attach(MIMEText(f"Your OTP is: {otp}", 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()

        return jsonify({'message': 'OTP sent successfully'})

    except Exception as e:
        print("OTP error:", str(e))
        return jsonify({'error': 'Failed to send OTP. Please try again.'}), 500

# 🔐 Reset Password
@app.route('/reset-password', methods=['POST'])
@cross_origin()
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        new_password = data.get('new_password')

        if not email or not otp or not new_password:
            return jsonify({'error': 'Missing fields'}), 400

        stored = otp_store.get(email)
        if not stored:
            return jsonify({'error': 'OTP not requested'}), 400

        if time.time() > stored.get('expiry', 0):
            otp_store.pop(email, None)
            return jsonify({'error': 'OTP expired'}), 400

        if otp != stored.get('otp'):
            return jsonify({'error': 'Invalid OTP'}), 400

        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users_col.update_one({'email': email}, {'$set': {'password': hashed_pw}})

        otp_store.pop(email, None)
        return jsonify({'message': 'Password updated successfully'})

    except Exception as e:
        print("Reset error:", str(e))
        return jsonify({'error': 'Password reset failed'}), 500
    
#admin can delete users 
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    admin_email = request.headers.get('X-User-Email')
    if admin_email != ALLOWED_USER_EMAIL:
        return jsonify({'error': 'Unauthorized'}), 403

    users = list(users_col.find({}, {'_id': 0, 'email': 1, 'username': 1}))
    return jsonify({'users': users})

@app.route('/api/admin/users/delete', methods=['POST'])
def delete_user():
    admin_email = request.headers.get('X-User-Email')
    if admin_email != ALLOWED_USER_EMAIL:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    result = users_col.delete_one({'email': email})
    if result.deleted_count == 1:
        return jsonify({'message': f'User {email} deleted successfully'})
    else:
        return jsonify({'error': 'User not found'}), 404


#these routes for trend anlysis thats not work 
@app.route('/api/trends/daily', methods=['GET'])
def get_daily_trends():
    data = load_json('daily_trends.json')
    return jsonify(data)

@app.route('/api/trends/mixmatch', methods=['GET'])
def get_mix_match():
    data = load_json('mix_match.json')
    return jsonify(data)

@app.route('/api/trends/global', methods=['GET'])
def get_global_trends():
    data = load_json('global_trends.json')
    return jsonify(data)

@app.route('/api/trends/toolkit', methods=['GET'])
def get_toolkit():
    data = load_json('toolkit.json')
    return jsonify(data)


#stylesuggestiionnnnnnnn

@app.route('/api/style/questions/<category>', methods=['GET'])
def get_style_questions(category):
    if category not in style_data:
        return jsonify({'error': 'Invalid category'}), 400

    questions = style_data[category]
    random.shuffle(questions)
    return jsonify(questions[:4])  # Send 4 random questions



@app.route('/api/style/answers', methods=['POST'])
def get_style_answers():
    data = request.get_json()
    category = data.get('category')
    question = data.get('question')

    if not category or not question:
        return jsonify({'error': 'Missing fields'}), 400

    question_set = next((q for q in style_data.get(category, []) if q["question"] == question), None)
    if not question_set:
        return jsonify({'error': 'Question not found'}), 404

    random.shuffle(question_set["answers"])
    return jsonify({'answers': question_set["answers"][:3]})

##contect form for cancel , exchnage , genralizationn............................................
@app.route('/api/contact', methods=['POST'])
def handle_contact():
    try:
        data = request.form
        name = data.get("name")
        email = data.get("email")
        message = data.get("message")
        mobile = data.get("mobile")
        reason = data.get("reason")
        order_date = data.get("order_date")
        query_type = data.get("queryType")

        # Setup email
        sender_email = os.getenv("EMAIL_USER")
        sender_pass = os.getenv("EMAIL_PASS")
        receiver_email = sender_email  # You’ll receive it

        if not sender_email or not sender_pass:
            return jsonify({'error': 'Server email not configured'}), 500

        subject = f"New Contact Submission - {query_type}"
        body = ""

        if query_type == "cancel":
            refund_msg = ""
            try:
                order_dt = datetime.datetime.strptime(order_date, "%Y-%m-%d")
                days_passed = (datetime.datetime.utcnow() - order_dt).days
                if days_passed <= 1:
                    refund_msg = "✅ Full refund will be processed."
                elif days_passed <= 3:
                    refund_msg = "🔁 40% refund will be processed."
                else:
                    refund_msg = "❌ No refund (cancellation too late)."

            except Exception as e:
                refund_msg = "⚠️ Unable to calculate refund."

            body = f"""CANCEL ORDER REQUEST:

Name: {name}
Email: {email}
Mobile: {mobile}
Order Date: {order_date}
Reason: {reason}
Refund Evaluation: {refund_msg}

📬 Please check and follow up manually.
"""
        else:
            body = f"""GENERAL QUERY / CUSTOMIZATION:

Name: {name}
Email: {email}
Message: {message}
"""

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # File (if exists)
        if 'bill' in request.files:
            bill = request.files['bill']
            filename = secure_filename(bill.filename)
            filepath = os.path.join("uploads", filename)
            bill.save(filepath)

            with open(filepath, "rb") as f:
                from email.mime.application import MIMEApplication
                part = MIMEApplication(f.read(), Name=filename)
                part['Content-Disposition'] = f'attachment; filename="{filename}"'
                msg.attach(part)

        # Send email
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        return jsonify({'message': 'Request submitted successfully!'})

    except Exception as e:
        print("Contact error:", str(e))
        return jsonify({'error': 'Failed to submit. Try again later.'}), 500

#part of aisection style suggesion .............................................
@app.route('/api/style/save', methods=['POST'])
def save_style_response():
    data = request.get_json()
    db.user_style_feedback.insert_one({
        "userId": data.get("userId", None),
        "category": data.get("category"),
        "question": data.get("question"),
        "answer": data.get("answer"),
        "timestamp": datetime.datetime.utcnow()
    })
    return jsonify({'message': 'Saved successfully'})
   
@app.route('/api/ai/style-suggestion', methods=['POST'])
def style_suggestion():
    data = request.json
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    try:
        from generate_text import generate_fashion_text
        suggestion = generate_fashion_text(prompt, max_length=100)
        return jsonify({'suggestion': suggestion})
    except Exception as e:
        return jsonify({'error': f"Generation error: {str(e)}"}), 500
#products based routes ...................................................................


# Assume products_col is your MongoDB collection
# from your_db_setup_file import products_col

# -------------------------------------------------------
# GET: All products
# @app.route('/api/products', methods=['GET'])
# def get_all_products():
#     try:
#         products = list(products_col.find())
#         for product in products:
#             product['_id'] = str(product['_id'])
#         return jsonify(products), 200
#     except Exception as e:
#         return jsonify({"error": f"Server error: {str(e)}"}), 500
@app.route('/api/products', methods=['GET'])
def get_all_products():
    try:
        query = {}
        if request.args.get('bestseller') == "true":
            query["bestseller"] = True

        products = list(products_col.find(query))
        for product in products:
            product['_id'] = str(product['_id'])
        return jsonify(products), 200
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# -------------------------------------------------------
# GET: Single product by ID (🔧 required for detail page)
@app.route('/api/products/<product_id>', methods=['GET'])
def get_product_by_id(product_id):
    if len(product_id) != 24 or not all(c in '0123456789abcdef' for c in product_id.lower()):
        return jsonify({"error": "Invalid product ID"}), 400

    try:
        product = products_col.find_one({"_id": ObjectId(product_id)})
        if not product:
            return jsonify({"error": "Product not found"}), 404

        product['_id'] = str(product['_id'])
        return jsonify(product), 200
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# -------------------------------------------------------
# POST: Add new product
@app.route('/api/products', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def add_product():
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON format'}), 400

    required_fields = ['name', 'price', 'image', 'description']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'{field} is required'}), 400

    try:
        price_value = float(data['price'])
    except ValueError:
        return jsonify({"error": "Invalid price format"}), 400

    new_product = {
        "name": data['name'],
        "price": price_value,
        "image": data['image'],  # ✅ image is full URL
        "images": data.get("images", []),
        "description": data['description'],
        "colors": data.get("colors", []),
        "sizes": data.get("sizes", []),
        "created_at": datetime.utcnow(),
    }

    try:
        result = products_col.insert_one(new_product)
        new_product['_id'] = str(result.inserted_id)
        return jsonify(new_product), 201
    except Exception as e:
        return jsonify({"error": f"Database insert error: {str(e)}"}), 500
#for trending products............................................................
@app.route('/api/products/trending', methods=['GET'])
def get_trending_products():
    try:
        # Sort by newest created_at, limit to 5
        trending = list(products_col.find().sort("created_at", -1).limit(5))

        for product in trending:
            product['_id'] = str(product['_id'])

        return jsonify(trending), 200

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# -------------------------------------------------------
# DELETE: Product by ID
@app.route('/api/products/<product_id>', methods=['DELETE', 'OPTIONS'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def delete_product(product_id):
    if request.method == 'OPTIONS':
        return '', 200

    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    if len(product_id) != 24 or not all(c in '0123456789abcdef' for c in product_id.lower()):
        return jsonify({"error": "Invalid product ID format"}), 400

    try:
        result = products_col.delete_one({"_id": ObjectId(product_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Product deleted successfully"}), 200
        else:
            return jsonify({"error": "Product not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# -------------------------------------------------------
# POST: Upload image (main + additional)
@app.route('/api/upload', methods=['POST'])
@cross_origin(supports_credentials=True, origins=["http://localhost:5173"])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    image = request.files['image']
    if image.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    # Create upload directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Generate unique filename to prevent collisions
    filename = secure_filename(image.filename)
    unique_filename = f"{datetime.now().timestamp()}_{filename}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        image.save(save_path)
        # Use request.host_url to make the URL dynamic
        image_url = f"{request.host_url}static/uploads/products/{unique_filename}"
        return jsonify({'url': image_url}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to save image: {str(e)}'}), 500

# Chatbot Flow
chatbot_flow = {
    "start": {
        "question": "What kind of fashion help do you need today?",
        "options": {
            "Party Look": "party_look",
            "College Outfit": "college_look",
            "Ethnic Wear": "ethnic_wear",
            "Seasonal Styling": "seasonal_style"
        }
    },
    "final_suggestion": {
        "question": "Tell us more about your preferences or any specific outfit idea you have in mind!",
        "input": True,
        "store_in_db": True
    }
}


#order relateddd ALL routes
#PAYMENT FLOW
@app.route("/api/create-order", methods=["POST"])
def create_razorpay_order():
    try:
        data = request.get_json()
        amount = data.get("amount")  # in rupees

        if not amount:
            return jsonify({"error": "Amount is required"}), 400

        amount_paise = int(float(amount) * 100)  # Convert to paise

        razorpay_order = razorpay_client.order.create({
            "amount": amount_paise,
            "currency": "INR",
            "payment_capture": 1,
        })

        return jsonify({
            "order_id": razorpay_order["id"],
            "amount": razorpay_order["amount"],
            "currency": razorpay_order["currency"]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/orders', methods=['POST'])
def save_order():
    data = request.get_json()
    email = data.get('email')
    items = data.get('items')
    total = data.get('total')
    address = data.get('deliveryAddress')
    status = data.get('status')
    order_date = data.get('orderDate')
    order_id = data.get('orderId')
    coupon_code = data.get('coupon_code')

    if not email or not items or not order_id:
        return jsonify({'error': 'Missing required fields'}), 400

    if orders_col.find_one({'orderId': order_id, 'email': email}):
        return jsonify({'message': 'Order already exists! Skipping duplicate save.'}), 200

    order = {
        'email': email,
        'items': items,
        'total': total,
        'deliveryAddress': address,
        'status': status,
        'orderDate': order_date,
        'orderId': order_id,
        'timestamp': datetime.utcnow(),
        'coupon_code': coupon_code if coupon_code else None,
        'delivered': False
    }

    orders_col.insert_one(order)

    try:
        sender_email = os.getenv("EMAIL_USER")
        sender_pass = os.getenv("EMAIL_PASS")
        receiver_email = email

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🛍️ Your Order #{order_id} is Confirmed!"
        msg["From"] = sender_email
        msg["To"] = receiver_email

        # Build HTML item lines separately
        item_lines_html = "".join([
            f'<div class="item"><strong>{item.get("name")}</strong> (Qty: {item.get("quantity", 1)}) - ₹{item.get("quantity", 1) * item.get("price")}</div>'
            for item in items
        ])

        # HTML Email Template
        current_year = datetime.now().year
        html = f"""
        <html>
          <head>
            <style>
              body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
              .header {{ color: #4a4a4a; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
              .order-details {{ background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0; }}
              .item {{ margin-bottom: 8px; }}
              .footer {{ margin-top: 20px; font-size: 0.9em; color: #777; }}
              .policy {{ background: #fff8e6; padding: 15px; border-left: 4px solid #ffc107; margin: 15px 0; }}
            </style>
          </head>
          <body>
            <div class="header">
              <h2>Thank you for your order!</h2>
              <p>Order #{order_id} • {order_date}</p>
            </div>

            <div class="order-details">
              <h3>Order Summary</h3>
              {item_lines_html}
              <hr>
              <div><strong>Total Amount:</strong> ₹{total}</div>
              <div><strong>Delivery Address:</strong> {address}</div>
              {f'<div><strong>Coupon Applied:</strong> {coupon_code}</div>' if coupon_code else ''}
            </div>

            <div class="policy">
              <h3>📢 Refund Policy:</h3>
              <p>✅ Same day or next day: Full refund</p>
              <p>⚠️ 2–3 days: 40% refund</p>
              <p>🚫 After 3 days: No refund</p>
              <small>We'll review your order and reply via email within 24 hours.</small>
            </div>

            <p>Your order status: <strong>{status}</strong></p>
            <p>We'll send you another email when your order ships.</p>

            <div class="footer">
              <p>Need help? Contact our support team at support@swadhin.com</p>
              <p>© {current_year} SWADHIN. All rights reserved.</p>
            </div>
          </body>
        </html>
        """

        # Plain text version
        item_lines_text = "".join([
            f"- {item.get('name')} (Qty: {item.get('quantity', 1)}) - ₹{item.get('quantity', 1) * item.get('price')}\n"
            for item in items
        ])

        text = f"""\
Hello,

Your order #{order_id} has been successfully placed on {order_date}.

🧾 Order Summary:
{item_lines_text}

Total Amount: ₹{total}
Delivery Address: {address}
Status: {status}
{"Coupon Applied: " + coupon_code if coupon_code else ''}

📢 Refund Policy:
✅ Same day or next day: Full refund
⚠️ 2–3 days: 40% refund
🚫 After 3 days: No refund
(We'll review your order and reply via email within 24 hours)

Thank you for shopping with SWADHIN 💖
        """

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_pass)
            server.sendmail(sender_email, receiver_email, msg.as_string())

    except Exception as e:
        print(f"❌ Email sending failed: {str(e)}")

    return jsonify({'message': 'Order saved and email sent successfully ✅'}), 201

@app.route('/api/orders/<order_id>/update-status', methods=['PATCH'])
def update_order_status(order_id):
    from datetime import datetime
    data = request.get_json()
    new_status = data.get('status')

    if not new_status:
        return jsonify({'error': 'Status is required'}), 400

    result = orders_col.update_one(
        {"_id": ObjectId(order_id)},
        {
            "$set": {
                "status": new_status,
                "statusUpdatedAt": datetime.utcnow()
            }
        }
    )

    if result.modified_count == 1:
        return jsonify({"message": "Order status updated successfully"}), 200
    else:
        return jsonify({"error": "Order not found or no changes made"}), 404



@app.route('/api/style-quiz', methods=['POST'])
def save_style_quiz():
    try:
        data = request.get_json()
        user_email = data.get('email')
        answers = data.get('answers')

        if not user_email or not answers:
            return jsonify({'error': 'Missing data'}), 400

        style_quiz_doc = {
            'email': user_email,
            'answers': answers,
            'timestamp': datetime.datetime.utcnow()
        }

        db.style_quiz_answers.insert_one(style_quiz_doc)
        return jsonify({'message': 'Quiz answers saved successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # ✅ FIX: Better error reporting

@app.route('/api/orders/<email>', methods=['GET'])
def get_orders(email):
    try:
        user_orders = list(orders_col.find({'email': email}))
        for o in user_orders:
            o['_id'] = str(o['_id'])
            o['delivered'] = o.get('delivered', False)  # ✅ FIX: Ensure delivered field exists
        return jsonify(user_orders), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # ✅ FIX: Added error handling

@app.route('/api/orders/<order_id>', methods=['DELETE'])
def delete_order(order_id):
    try:
        result = orders_col.delete_one({'_id': ObjectId(order_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Order not found'}), 404
        return jsonify({'message': 'Order deleted successfully'}), 200
    except Exception as e:  # ✅ FIX: Catch specific exception
        return jsonify({'error': f'Invalid order ID: {str(e)}'}), 400

@app.route('/api/orders/clear-all', methods=['POST'])
def clear_all_orders():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = users_col.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'error': 'Incorrect password'}), 403

    result = orders_col.delete_many({'email': email})
    return jsonify({'message': f'{result.deleted_count} orders deleted successfully'}), 200

# GET - Admin: Get all orders
@app.route('/api/orders', methods=['GET'])
def get_all_orders():
    user_email = request.headers.get("X-User-Email")
    if user_email != ALLOWED_USER_EMAIL:
        return jsonify({"error": "Unauthorized access"}), 401

    try:
        all_orders = list(orders_col.find())
        for o in all_orders:
            o['_id'] = str(o['_id'])
            o['delivered'] = o.get('delivered', False)  # ✅ FIX: Ensure delivered field exists
        return jsonify(all_orders), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500        

# PUT - Mark order as delivered
@app.route('/api/orders/<order_id>/deliver', methods=['PUT'])
def mark_as_delivered(order_id):
    try:
        result = orders_col.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'delivered': True, 'status': 'Delivered'}}  # ✅ FIX: Added status update
        )
        if result.matched_count == 0:
            return jsonify({'error': 'Order not found'}), 404
        return jsonify({'message': 'Order marked as delivered'}), 200
    except Exception as e:
        return jsonify({'error': f'Invalid order ID: {str(e)}'}), 400


#reviews related all routes 
@app.route('/api/reviews/<product_id>', methods=['POST'])
def add_review(product_id):
    try:
        data = request.get_json()
        email = data.get("email")
        comment = data.get("comment")
        rating = data.get("rating")
        verified_buyer = data.get("verifiedBuyer", False)

        # Validate required fields
        if not all([email, comment, rating]):
            return jsonify({"error": "Missing required fields: email, comment, rating"}), 400

        # Validate rating is between 1-5
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Rating must be an integer between 1 and 5"}), 400

        # Check for existing review from this user
        if product_reviews_collection.find_one({"productId": product_id, "email": email}):
            return jsonify({"error": "You have already reviewed this product"}), 409

        # Create new review
        review = {
            "productId": product_id,
            "email": email,
            "comment": comment.strip(),
            "rating": rating,
            "verifiedBuyer": verified_buyer,
            "reactions": {},  # {user_email: "like"/"dislike"}
            "timestamp": datetime.now()
        }

        result = product_reviews_collection.insert_one(review)
        
        return jsonify({
            "message": "Review added successfully",
            "reviewId": str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route('/api/reviews/<review_id>/react', methods=['POST'])
def toggle_reaction(review_id):
    try:
        data = request.get_json()
        user_email = data.get("email")
        action = data.get("action")  # 'like' or 'dislike'

        # Validate input
        if not user_email or action not in ['like', 'dislike']:
            return jsonify({"error": "Invalid data: email and valid action required"}), 400

        # Get the review
        review = product_reviews_collection.find_one({"_id": ObjectId(review_id)})
        if not review:
            return jsonify({"error": "Review not found"}), 404

        # Prevent self-reaction
        if review.get("email") == user_email:
            return jsonify({"error": "You cannot react to your own review"}), 403

        reactions = review.get("reactions", {})
        previous_action = reactions.get(user_email)

        # Toggle logic
        if previous_action == action:
            # Remove reaction if same action clicked again
            reactions.pop(user_email)
        else:
            # Set new reaction
            reactions[user_email] = action

        # Update in database
        product_reviews_collection.update_one(
            {"_id": ObjectId(review_id)},
            {"$set": {"reactions": reactions}}
        )

        # Get updated counts
        updated_review = product_reviews_collection.find_one({"_id": ObjectId(review_id)})
        reactions = updated_review.get("reactions", {})
        likes = sum(1 for v in reactions.values() if v == "like")
        dislikes = sum(1 for v in reactions.values() if v == "dislike")

        return jsonify({
            "message": "Reaction updated",
            "likes": likes,
            "dislikes": dislikes,
            "userAction": reactions.get(user_email)  # Current user's action
        }), 200

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route('/api/reviews/<product_id>', methods=['GET'])
def get_reviews(product_id):
    try:
        # Optional query parameters
        sort_by = request.args.get('sort', 'timestamp')  # 'timestamp' or 'rating'
        sort_order = -1 if request.args.get('order', 'desc') == 'desc' else 1
        
        # Build query
        query = {"productId": product_id}
        
        # Get reviews from database
        reviews_cursor = product_reviews_collection.find(query).sort(sort_by, sort_order)
        
        # Process reviews
        reviews = []
        for review in reviews_cursor:
            reactions = review.get("reactions", {})
            likes = sum(1 for v in reactions.values() if v == "like")
            dislikes = sum(1 for v in reactions.values() if v == "dislike")

            reviews.append({
                "_id": str(review.get("_id")),
                "email": review.get("email"),
                "comment": review.get("comment"),
                "rating": review.get("rating"),
                "verifiedBuyer": review.get("verifiedBuyer", False),
                "likes": likes,
                "dislikes": dislikes,
                "timestamp": review.get("timestamp").strftime('%Y-%m-%d %H:%M:%S'),
                "reactions": reactions  # Send full reactions for frontend highlighting
            })

        # Calculate average rating
        avg_rating = 0
        if reviews:
            avg_rating = sum(r['rating'] for r in reviews) / len(reviews)

        return jsonify({
            "reviews": reviews,
            "averageRating": round(avg_rating, 1),
            "totalReviews": len(reviews)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ⚙️ Upload Folder Setup
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ✅ POST: Upload Lookbook Post (CORS fix)
@app.route('/api/lookbook', methods=['POST', 'OPTIONS'])
@cross_origin(origins=["http://localhost:5173"])
def upload_lookbook_post():
    if request.method == 'OPTIONS':
        return jsonify({'message': 'CORS preflight success'}), 200

    image_file = request.files.get('media')
    caption = request.form.get('caption')
    email = request.form.get('email')

    if not image_file or not caption or not email:
        return jsonify({'error': 'Missing fields'}), 400

    filename = secure_filename(image_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image_file.save(filepath)

    file_url = f"http://localhost:5000/uploads/{filename}"
    post = {
        'imageUrl': file_url,
        'caption': caption,
        'email': email,
        'likes': [],
        'unlocked_coupons': [],
        'timestamp': datetime.utcnow()
    }
    lookbook_collection.insert_one(post)

    return jsonify({
        'message': 'Your post has been successfully uploaded 🎉 You can view it in the User Gallery.'
    }), 200

# ✅ ADD THIS BELOW your existing routes
@app.route('/api/lookbook/like', methods=['POST'])
@cross_origin()
def like_or_unlike_look():
    data = request.get_json()
    post_id = data.get('postId')
    email = data.get('email')
    action = data.get('action', 'like')

    if not post_id or not email:
        return jsonify({'error': 'Post ID and email required'}), 400

    try:
        post_obj_id = ObjectId(post_id)
        post = lookbook_collection.find_one({"_id": post_obj_id})

        if not post:
            return jsonify({'error': 'Post not found'}), 404

        post_owner_email = post.get("email")  # 📌 This is the post creator

        if action == 'like':
            if email in post.get('likes', []):
                return jsonify({'message': 'Already liked'}), 200

            # ✅ Add the like
            lookbook_collection.update_one(
                {"_id": post_obj_id},
                {"$addToSet": {"likes": email}}
            )

            # Get updated post with new like count
            updated_post = lookbook_collection.find_one({"_id": post_obj_id})
            total_likes = len(updated_post.get("likes", []))

            # 🔓 Unlock only for post owner, not the liker
            matching_coupons = coupon_collection.find({
                "min_likes_to_unlock": total_likes,
                "active": True,
                "code": {"$nin": updated_post.get("unlocked_coupons", [])}
            })

            unlocked_coupons = []
            for coupon in matching_coupons:
                if coupon.get("expiry_date"):
                    expiry = datetime.strptime(coupon["expiry_date"], "%Y-%m-%d").date()
                    if datetime.utcnow().date() > expiry:
                        continue

                if coupon.get("max_uses", 0) > 0 and coupon.get("current_uses", 0) >= coupon["max_uses"]:
                    continue

                coupon_code = coupon["code"]

                # ✅ Mark as unlocked on the post
                lookbook_collection.update_one(
                    {"_id": post_obj_id},
                    {"$addToSet": {"unlocked_coupons": coupon_code}}
                )

                # ✅ Grant to **post owner**, not the liker
                db.unlocked_coupons.update_one(
                    {"email": post_owner_email, "code": coupon_code},
                    {"$set": {
                        "post_id": post_id,
                        "unlocked_at": datetime.utcnow(),
                        "seen": False,
                        "used": False
                    }},
                    upsert=True
                )

                unlocked_coupons.append({
                    "code": coupon_code,
                    "amount": coupon["amount"],
                    "discount_type": coupon["discount_type"],
                    "description": coupon.get("description", "")
                })

            response = {"message": "Liked successfully"}
            if unlocked_coupons:
                response["unlocked_coupons"] = unlocked_coupons

            return jsonify(response), 200

        elif action == 'unlike':
            if email not in post.get('likes', []):
                return jsonify({'message': 'Already unliked'}), 200

            lookbook_collection.update_one(
                {"_id": post_obj_id},
                {"$pull": {"likes": email}}
            )
            return jsonify({'message': 'Unliked successfully'}), 200

        else:
            return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        print("Like/Unlike error:", str(e))
        return jsonify({'error': 'Internal server error'}), 500

    
# ✅ GET: All Lookbook Posts
@app.route('/api/lookbook', methods=['GET'])
def get_lookbook_posts():
    posts = list(lookbook_collection.find())
    for post in posts:
        post['_id'] = str(post['_id'])
    return jsonify(posts)

@app.route('/api/lookbook/<post_id>', methods=['DELETE'])
def delete_lookbook_post(post_id):
    try:
        post_obj_id = ObjectId(post_id)
        result = lookbook_collection.delete_one({"_id": post_obj_id})

        if result.deleted_count == 1:
            return jsonify({'message': 'Post deleted successfully'}), 200
        else:
            return jsonify({'error': 'Post not found'}), 404
    except Exception as e:
        print("Delete error:", e)
        return jsonify({'error': 'Internal server error'}), 500

# ✅ Media file serving
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Decorator for admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_email = request.headers.get("X-User-Email")
        if user_email != ALLOWED_USER_EMAIL:
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function
#coupns based all routess.........................................................
@app.route('/api/admin/coupons', methods=['POST'])
@admin_required
def create_coupon():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['code', 'discount_type', 'amount']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate discount type
        if data['discount_type'] not in ['percentage', 'fixed']:
            return jsonify({"error": "Invalid discount type"}), 400

        # Validate amount based on discount type
        if data['discount_type'] == 'percentage' and not (0 < float(data['amount']) <= 100):
            return jsonify({"error": "Percentage must be between 0 and 100"}), 400
        elif data['discount_type'] == 'fixed' and float(data['amount']) <= 0:
            return jsonify({"error": "Fixed amount must be positive"}), 400

        # Check for duplicate code
        existing = coupon_collection.find_one({"code": data['code'].upper()})
        if existing:
            return jsonify({"error": "Coupon code already exists"}), 400

        # Validate expiry date format if provided
        expiry_date = data.get('expiry_date')
        if expiry_date:
            try:
                datetime.strptime(expiry_date, "%Y-%m-%d")
            except ValueError:
                return jsonify({"error": "Invalid expiry date format. Use YYYY-MM-DD"}), 400

        # Convert product_ids from string to array if provided
        product_ids = []
        if data.get('applies_to') == 'product' and data.get('product_ids'):
            product_ids = [pid.strip() for pid in data['product_ids'].split(',') if pid.strip()]
            if not product_ids:
                return jsonify({"error": "At least one valid product ID required"}), 400

        coupon_data = {
            "code": data['code'].upper(),
            "discount_type": data['discount_type'],
            "amount": float(data['amount']),
            "applies_to": data.get('applies_to', 'all'),
            "product_ids": product_ids,
            "expiry_date": expiry_date,
            "min_order_price": float(data.get('min_order_price', 0)),
            "min_likes_to_unlock": int(data.get('min_likes_to_unlock', 0)),
            "max_uses": int(data.get('max_uses', 0)),
            "current_uses": 0,
            "created_at": datetime.utcnow(),
            "active": bool(data.get('active', True)),
            "single_use": bool(data.get('single_use', True)),
            "description": data.get('description', ''),
            "triggered_for_users": []
        }

        coupon_collection.insert_one(coupon_data)
        return jsonify({"message": "Coupon created successfully", "code": data['code'].upper()}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/coupons', methods=['GET'])
@cross_origin()
def get_all_active_coupons():
    try:
        today = datetime.utcnow().date()
        coupons = list(coupon_collection.find({
            "active": True,
            "$or": [
                {"expiry_date": {"$exists": False}},
                {"expiry_date": {"$gte": today.strftime("%Y-%m-%d")}}
            ]
        }))
        for coupon in coupons:
            coupon["_id"] = str(coupon["_id"])
            coupon.pop("triggered_for_users", None)
            coupon.pop("current_uses", None)

        return jsonify(coupons), 200
    except Exception as e:
        return jsonify({"error": "Failed to fetch coupons"}), 500

@app.route('/api/admin/coupons', methods=['GET'])
@admin_required
def get_all_coupons_admin():
    try:
        coupons = list(coupon_collection.find({}).sort("created_at", -1))
        for coupon in coupons:
            coupon["_id"] = str(coupon["_id"])
            # Calculate usage percentage if max_uses is set
            if coupon.get("max_uses", 0) > 0:
                coupon["usage_percentage"] = (coupon.get("current_uses", 0) / coupon["max_uses"]) * 100
        return jsonify(coupons)
    except Exception as e:
        return jsonify({"error": "Failed to fetch coupons"}), 500

@app.route('/api/admin/coupons/<code>', methods=['DELETE'])
@admin_required
def delete_coupon(code):
    try:
        result = coupon_collection.delete_one({"code": code.upper()})
        if result.deleted_count == 0:
            return jsonify({"error": "Coupon not found"}), 404

        # Also clean up any references to this coupon
        db.used_coupons.update_many(
            {},
            {"$pull": {"codes": code.upper()}}
        )
        db.coupon_orders.delete_many({"coupon_code": code.upper()})

        return jsonify({"message": "Coupon deleted successfully"})
    except Exception as e:
        return jsonify({"error": "Failed to delete coupon"}), 500

@app.route('/api/admin/coupons/<code>/toggle', methods=['PUT'])
@admin_required
def toggle_coupon_status(code):
    try:
        coupon = coupon_collection.find_one({"code": code.upper()})
        if not coupon:
            return jsonify({"error": "Coupon not found"}), 404

        new_status = not coupon.get("active", True)
        coupon_collection.update_one(
            {"code": code.upper()},
            {"$set": {"active": new_status}}
        )

        return jsonify({
            "message": "Coupon status updated",
            "code": code.upper(),
            "active": new_status
        })
    except Exception as e:
        return jsonify({"error": "Failed to update coupon status"}), 500

@app.route('/api/coupons/validate', methods=['GET'])
@cross_origin()
def validate_coupon():
    try:
        code = request.args.get('code', '').upper()
        product_id = request.args.get('product_id')
        user_email = request.args.get('user_email')

        if not code:
            return jsonify({"error": "Coupon code is required"}), 400

        coupon = coupon_collection.find_one({"code": code, "active": True})
        if not coupon:
            return jsonify({"error": "Invalid coupon code"}), 404

        # Check expiry
        if coupon.get("expiry_date"):
            expiry = datetime.strptime(coupon["expiry_date"], "%Y-%m-%d").date()
            if datetime.utcnow().date() > expiry:
                return jsonify({"error": "Coupon has expired"}), 400

        # Check max uses
        if coupon.get("max_uses", 0) > 0 and coupon.get("current_uses", 0) >= coupon["max_uses"]:
            return jsonify({"error": "Coupon usage limit reached"}), 400

        # Check if user has already used this single-use coupon
        if user_email and coupon.get("single_use", True):
            if user_email.lower() in coupon.get("triggered_for_users", []):
                return jsonify({"error": "You've already used this coupon"}), 400

        # Check product applicability
        if coupon.get("applies_to") == "product" and product_id:
            if product_id not in coupon.get("product_ids", []):
                return jsonify({"error": "Coupon not valid for this product"}), 400

        # Prepare response
        response = {
            "code": coupon["code"],
            "discount_type": coupon["discount_type"],
            "amount": coupon["amount"],
            "min_order_price": coupon.get("min_order_price", 0)
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": "Failed to validate coupon"}), 500

@app.route('/api/coupons/apply', methods=['POST'])
@cross_origin()
def apply_coupon():
    try:
        data = request.get_json()
        code = data.get('code', '').upper()
        user_email = data.get('user_email')
        order_amount = float(data.get('order_amount', 0))
        product_ids = data.get('product_ids', [])

        if not code or not user_email:
            return jsonify({"error": "Missing required fields"}), 400

        # Validate the coupon
        coupon = coupon_collection.find_one({"code": code, "active": True})
        if not coupon:
            return jsonify({"error": "Invalid coupon code"}), 404

        # Check expiry
        if coupon.get("expiry_date"):
            expiry = datetime.strptime(coupon["expiry_date"], "%Y-%m-%d").date()
            if datetime.utcnow().date() > expiry:
                return jsonify({"error": "Coupon has expired"}), 400

        # Check max uses
        if coupon.get("max_uses", 0) > 0 and coupon.get("current_uses", 0) >= coupon["max_uses"]:
            return jsonify({"error": "Coupon usage limit reached"}), 400

        # Check single use
        if coupon.get("single_use", True):
            if user_email.lower() in coupon.get("triggered_for_users", []):
                return jsonify({"error": "You've already used this coupon"}), 400

        # Check minimum order price
        if order_amount < coupon.get("min_order_price", 0):
            return jsonify({
                "error": f"Order amount must be at least {coupon['min_order_price']}",
                "min_order_price": coupon["min_order_price"]
            }), 400

        # Check product applicability
        if coupon.get("applies_to") == "product" and product_ids:
            valid_products = set(product_ids) & set(coupon.get("product_ids", []))
            if not valid_products:
                return jsonify({"error": "Coupon not valid for any products in your order"}), 400

        # Calculate discount
        if coupon["discount_type"] == "percentage":
            discount_amount = min(order_amount * coupon["amount"] / 100, order_amount)
        else:
            discount_amount = min(coupon["amount"], order_amount)

        response = {
            "code": coupon["code"],
            "discount_type": coupon["discount_type"],
            "amount": coupon["amount"],
            "discount_amount": discount_amount,
            "final_amount": order_amount - discount_amount
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": "Failed to apply coupon"}), 500

@app.route('/api/coupons/confirm-use', methods=['POST'])
@cross_origin()
def confirm_coupon_use():
    try:
        data = request.get_json()
        code = data.get('code', '').upper()
        user_email = data.get('user_email')
        order_id = data.get('order_id')

        if not code or not user_email or not order_id:
            return jsonify({"error": "Missing required fields"}), 400

        # Verify coupon exists and is active
        coupon = coupon_collection.find_one({"code": code, "active": True})
        if not coupon:
            return jsonify({"error": "Invalid coupon code"}), 404

        # Check if this order already used this coupon
        existing_order = db.coupon_orders.find_one({"order_id": order_id})
        if existing_order:
            return jsonify({"error": "Coupon already applied to this order"}), 400

        # Check single use per customer
        if coupon.get("single_use", True):
            if user_email.lower() in coupon.get("triggered_for_users", []):
                return jsonify({"error": "Coupon already used by this customer"}), 400

        # Update coupon usage count
        coupon_collection.update_one(
            {"code": code},
            {
                "$inc": {"current_uses": 1},
                "$addToSet": {"triggered_for_users": user_email.lower()}
            }
        )

        # Record coupon-order association
        db.coupon_orders.insert_one({
            "order_id": order_id,
            "coupon_code": code,
            "user_email": user_email.lower(),
            "used_at": datetime.utcnow()
        })

        return jsonify({"message": "Coupon use confirmed"})

    except Exception as e:
        return jsonify({"error": "Failed to confirm coupon use"}), 500

@app.route('/api/user/coupons/available', methods=['GET'])
@cross_origin()
def get_available_coupons_for_user():
    try:
        user_email = request.args.get('email')
        if not user_email:
            return jsonify({"error": "Email is required"}), 400

        # Get all active coupons
        today = datetime.utcnow().date()
        active_coupons = list(coupon_collection.find({
            "active": True,
            "$or": [
                {"expiry_date": {"$exists": False}},
                {"expiry_date": {"$gte": today.strftime("%Y-%m-%d")}}
            ]
        }))

        # Filter out coupons the user has already used (for single-use coupons)
        available_coupons = []
        for coupon in active_coupons:
            if not coupon.get("single_use", True) or user_email.lower() not in coupon.get("triggered_for_users", []):
                # Remove sensitive fields
                coupon_data = {
                    "code": coupon["code"],
                    "discount_type": coupon["discount_type"],
                    "amount": coupon["amount"],
                    "applies_to": coupon.get("applies_to", "all"),
                    "min_order_price": coupon.get("min_order_price", 0),
                    "expiry_date": coupon.get("expiry_date"),
                    "description": coupon.get("description", ""),
                    "min_likes_to_unlock": coupon.get("min_likes_to_unlock", 0)
                }
                available_coupons.append(coupon_data)

        return jsonify(available_coupons)
    except Exception as e:
        return jsonify({"error": "Failed to fetch available coupons"}), 500

@app.route('/api/user/unlocked-coupons/<email>', methods=['GET'])
@cross_origin()
def get_unlocked_coupons(email):
    try:
        if not email:
            return jsonify({"error": "Email is required"}), 400

        today = datetime.utcnow().date()

        # Fetch unlocked coupons for this user
        unlocked_entries = list(db.unlocked_coupons.find({"email": email.lower(), "used": False}))

        unlocked = []
        for entry in unlocked_entries:
            coupon = coupon_collection.find_one({"code": entry["code"], "active": True})
            if not coupon:
                continue

            # Expiry check
            if coupon.get("expiry_date"):
                expiry = datetime.strptime(coupon["expiry_date"], "%Y-%m-%d").date()
                if today > expiry:
                    continue

            unlocked.append({
                "code": coupon["code"],
                "discount_type": coupon["discount_type"],
                "amount": coupon["amount"],
                "applies_to": coupon.get("applies_to", "all"),
                "min_order_price": coupon.get("min_order_price", 0),
                "expiry_date": coupon.get("expiry_date"),
                "description": coupon.get("description", ""),
                "type": "post-based",
                "post_id": entry.get("post_id"),
                "unlocked_at": entry.get("unlocked_at"),
                "seen": entry.get("seen", False)
            })

        return jsonify(unlocked), 200

    except Exception as e:
        print("Coupon unlock error:", e)
        return jsonify({"error": "Failed to fetch unlocked coupons"}), 500


@app.route('/api/user/mark-coupons-seen', methods=['POST'])
@cross_origin()
def mark_coupons_seen():
    try:
        data = request.get_json()
        email = data.get('email')
        codes = data.get('codes', [])

        if not email or not codes:
            return jsonify({"error": "Email and codes are required"}), 400

        for code in codes:
            coupon_collection.update_one(
                {"code": code.upper()},
                {"$addToSet": {"seen_by_users": email.lower()}}
            )

        return jsonify({"message": "Coupons marked as seen"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to mark coupons as seen"}), 500
    

# POST - Toggle Like/Dislike Reaction
# Run App
if __name__ == "__main__":
    # app.run(debug=True)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

