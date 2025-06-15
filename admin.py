from functools import wraps
import uuid
from flask import Flask, abort, jsonify, make_response, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import ASCENDING, MongoClient
from bson.objectid import ObjectId
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename 
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_wtf import CSRFProtect

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY']= 'Sasank0099@' 
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = False

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
mongo_uri = "mongodb+srv://Sasank0099:Vv6MtscDKXHhn1QR@cluster0.68ku4.mongodb.net/"
client = MongoClient(mongo_uri)
db = client.get_database('ecommerce')

# Collections
admins = db.admins
users = db.users
order_collections = db.orders
veg_sandwiches_collection = db.veg_sandwiches
non_veg_sandwiches_collection = db.non_veg_sandwichs

# Upload folder config
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# --- Helper decorators ---
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in') or session.get('admin_role') not in ['admin', 'manager']:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('admin_login'))

# Create default admin if not exists
default_admin_username = 'admin'
default_admin_password = 'admin123'  # CHANGE this in production
existing_admin = admins.find_one({'username': default_admin_username})

if not existing_admin:
    hashed_password = generate_password_hash(default_admin_password)
    admins.insert_one({
        'username': default_admin_username,
        'password_hash': hashed_password,
        'role': 'admin',
        'created_at': datetime.utcnow()
    })
    print(f"[INFO] Default admin created: {default_admin_username} / {default_admin_password}")
else:
    print("[INFO] Default admin already exists.")
    # Create default manager if not exists
default_manager_username = 'manager1'
default_manager_password = 'manager@123'  # CHANGE this in production
existing_manager = admins.find_one({'username': default_manager_username})

if not existing_manager:
    hashed_password = generate_password_hash(default_manager_password)
    admins.insert_one({
        'username': default_manager_username,
        'password_hash': hashed_password,
        'role': 'manager',
        'created_at': datetime.utcnow()
    })
    print(f"[INFO] Default manager created: {default_manager_username} / {default_manager_password}")
else:
    print("[INFO] Default manager already exists.")


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('admin/login.html', error="Please enter username and password")

        admin = admins.find_one({'username': username})
        if admin and check_password_hash(admin.get('password_hash', ''), password):
            role = admin.get('role', '').lower()
            if role in ['admin', 'manager']:
                session['admin_logged_in'] = True
                session['admin_username'] = username
                session['admin_role'] = role
                return redirect(url_for('admin_dashboard'))
            else:
                return render_template('admin/login.html', error="Access denied: Only Admin or Manager allowed")
        else:
            return render_template('admin/login.html', error="Invalid credentials")

    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


from flask import session, render_template
from datetime import datetime, timedelta

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    # Basic counts for all roles
    veg_count = veg_sandwiches_collection.count_documents({})
    non_veg_count = non_veg_sandwiches_collection.count_documents({})
    total_orders = order_collections.count_documents({})
    
    # Determine role from session
    role = session.get('admin_role')  # 'admin' or 'manager'
    is_admin = role == 'admin'

    # Only show total users to admins
    total_users = None
    if is_admin:
        total_users = users.count_documents({'role': {'$ne': 'manager'}})  # Exclude managers from count

    # Recent orders (for both roles)
    recent_orders = list(order_collections.find().sort('order_date', -1).limit(10))

    # Define time ranges
    today = datetime.today()
    start_of_day = datetime(today.year, today.month, today.day)
    start_of_week = start_of_day - timedelta(days=start_of_day.weekday())
    start_of_month = datetime(today.year, today.month, 1)

    # Aggregate sales totals (only for admin)
    def get_sales_total(start_date):
        pipeline = [
            {'$match': {'order_date': {'$gte': start_date}, 'status': 'delivered'}},
            {'$group': {'_id': None, 'total': {'$sum': '$total_price'}}}
        ]
        result = list(order_collections.aggregate(pipeline))
        return result[0]['total'] if result else 0

    daily_sales = get_sales_total(start_of_day) if is_admin else 0
    weekly_sales = get_sales_total(start_of_week) if is_admin else 0
    monthly_sales = get_sales_total(start_of_month) if is_admin else 0

    return render_template('admin/admin_dashboard.html',
                           veg_count=veg_count,
                           non_veg_count=non_veg_count,
                           total_orders=total_orders,
                           total_users=total_users,
                           recent_orders=recent_orders,
                           daily_sales=daily_sales,
                           weekly_sales=weekly_sales,
                           monthly_sales=monthly_sales,
                           is_admin=is_admin,
                           role=role)



@app.route('/admin/users')
@admin_login_required
def view_users():
    if session.get('admin_role') != 'admin':
        abort(403)
    all_users = list(users.find({}))
    return render_template('admin/users.html', users=all_users)

@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@admin_login_required
def delete_user(user_id):
    if session.get('admin_role') != 'admin':
        abort(403)
    users.delete_one({'_id': ObjectId(user_id)})
    return redirect(url_for('view_users'))


# Mock admin login check
def admin_login_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route("/admin_sandwiches")
@admin_login_required
def admin_sandwiches():
    return render_template("admin/admin_sandwiches.html")

@app.route("/get_sandwiches")
@admin_login_required
def get_sandwiches():
    veg = list(veg_sandwiches_collection.find())
    non_veg = list(non_veg_sandwiches_collection.find())
    for s in veg + non_veg:
        s["_id"] = str(s["_id"])
    return jsonify({"veg": veg, "non_veg": non_veg})

@app.route("/add_sandwich", methods=["POST"])
@admin_login_required
def add_sandwich():
    try:
        name = request.form["name"]
        price = float(request.form["price"])
        category = request.form["category"]
        image = request.files.get("image")

        if image and image.filename != "":
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(image_path)
            image_url = "/" + image_path.replace("\\", "/")
        else:
            image_url = "/static/images/default.jpg"

        sandwich = {
            "name": name,
            "price": price,
            "image_url": image_url,
            "category": category,
            "added_on": datetime.now()
        }

        if category.lower() == "veg":
            veg_sandwiches_collection.insert_one(sandwich)
        else:
            non_veg_sandwiches_collection.insert_one(sandwich)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/edit_sandwich", methods=["POST"])
@admin_login_required
def edit_sandwich():
    data = request.get_json()
    try:
        original_name = data["original_name"]
        name = data["name"]
        price = float(data["price"])
        image_url = data.get("image_url")
        category = data["category"]

        collection = veg_sandwiches_collection if category.lower() == "veg" else non_veg_sandwiches_collection
        collection.update_one({"name": original_name}, {"$set": {
            "name": name,
            "price": price,
            "image_url": image_url
        }})

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/delete_sandwich", methods=["POST"])
@admin_login_required
def delete_sandwich():
    data = request.get_json()
    try:
        name = data["name"]
        category = data["category"]

        # Normalize category to lowercase without hyphen for matching
        category_normalized = category.lower().replace("-", "").strip()

        if category_normalized == "veg":
            collection = veg_sandwiches_collection
        elif category_normalized in ["nonveg", "non-veg"]:
            collection = non_veg_sandwiches_collection
        else:
            return jsonify({"success": False, "message": "Invalid category"})

        delete_result = collection.delete_one({"name": name})

        if delete_result.deleted_count == 0:
            return jsonify({"success": False, "message": "No matching sandwich found"})

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

