import os
from datetime import datetime, timedelta
from functools import wraps
import uuid
import random
from wtforms.validators import DataRequired, Optional, NumberRange
from flask import Flask, Response, abort, json, jsonify, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, ASCENDING, ReturnDocument
from bson import ObjectId
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from yaml import serialize_all
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, DateField, SubmitField
from wtforms.validators import DataRequired
from datetime import datetime
class CouponForm(FlaskForm):
    code = StringField('Coupon Code', validators=[DataRequired()])
    discount = IntegerField('Discount (%)', validators=[DataRequired()])
    expiry = DateField('Expiry Date', validators=[DataRequired()])
    submit = SubmitField('Create Coupon')


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

from flask import Flask
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Must be set for CSRF to work
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["UPLOAD_FOLDER"] = "static/uploads"


# CSRF
csrf = CSRFProtect()
csrf.init_app(app)

# Flask-Mail
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER')
)
mail = Mail(app)


# Connect to MongoDB Atlas
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    # fallback to hardcoded URI if needed
    mongo_uri = "mongodb+srv://Sasank0099:Sasank0099@cluster0.68ku4.mongodb.net/"

client = MongoClient(mongo_uri)
db = client['ecommerce']

# Collections
users_collection = db['users']

# Ensure unique index on username
users_collection.create_index([("username", ASCENDING)], unique=True)


# Collections
users_collection = db.users
otp_collection = db.otps
sessions_collection = db.sessions
addresses_collection = db.addresses
veg_sandwiches_collection = db.veg_sandwiches
non_veg_sandwiches_collection = db.non_veg_sandwiches
orders_collection = db.orders
cart_collection = db.cart
save_later_collection = db.save_later
cards_collection = db.cards
upis_collection = db.upis
bank_accounts_collection = db.bank_accounts
wallets_collection = db.wallets
coupons_collection = db.coupons
notifications_collection = db.notifications
wishlist_collection = db.wishlist
reviews_collection = db.reviews
admins_collections=db.admin

# Create indexes
users_collection.create_index([("username", ASCENDING)], unique=True)
users_collection.create_index([("email", ASCENDING)], unique=True)
orders_collection.create_index([("user_id", ASCENDING)])
cart_collection.create_index([("user_id", ASCENDING)])
from flask_wtf.csrf import generate_csrf
from flask_mail import Mail

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vinnakotasasanknadiu@gmail.com'
app.config['MAIL_PASSWORD'] = 'lfqb xxyf slvc qtcz'
app.config['MAIL_DEFAULT_SENDER'] = 'vinnakotasasanknadiu@gmail.com'  # ✅ required

mail = Mail(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        return users_collection.find_one({'_id': ObjectId(session['user_id'])})
    return None

def generate_otp():
    return str(random.randint(100000, 999999))

from flask_mail import Message

def send_email(to, subject, body, html=None):
    try:
        msg = Message(subject, recipients=[to])  # No need to set sender manually
        msg.body = body
        if html:
            msg.html = html
        mail.send(msg)
        return True
    except Exception as e:
        print("Failed to send email:", str(e))
        return False


# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('login'))

        user = users_collection.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            if user.get('is_verified', False):
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                
                # Record login session
                sessions_collection.insert_one({
                    'user_id': user['_id'],
                    'session_id': str(uuid.uuid4()),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'login_time': datetime.utcnow(),
                    'last_activity': datetime.utcnow(),
                    'active': True
                })
                
                flash(f"Welcome back, {user['username']}!", 'success')
                return redirect(url_for('main'))
            else:
                flash('Please verify your email.', 'warning')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('customer/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()

        # Validation
        if not all([username, password, email, phone]):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('signup'))

        # Check if user exists
        if users_collection.find_one({'$or': [{'username': username}, {'email': email}]}):
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('signup'))

        # Generate OTP
        otp = generate_otp()
        otp_expiry = datetime.utcnow() + timedelta(minutes=15)

        # Store in database
        otp_collection.insert_one({
            "username": username,
            "email": email,
            "otp": otp,
            "type": "email",
            "used": False,
            "expires_at": otp_expiry,
            "created_at": datetime.utcnow()
        })

        # Prepare email
        email_body = f"""\
Hello {username},

Thank you for signing up at MySandwich!

Your verification code is: {otp}

This code will expire in 15 minutes.

If you didn't request this, please ignore this email.

Best regards,
MySandwich Team
"""

        email_html = f"""\
<html>
  <body>
    <h2>Welcome to MySandwich!</h2>
    <p>Your verification code is: <strong>{otp}</strong></p>
    <p>This code expires in 15 minutes.</p>
  </body>
</html>
"""

        # Send email
        if send_email(email, "Verify Your Email", email_body, email_html):
            session['pending_user'] = {
                'username': username,
                'password': generate_password_hash(password),
                'email': email,
                'phone': phone
            }
            flash('Verification email sent. Please check your inbox.', 'info')
            return redirect(url_for('verify_email'))
        else:
            flash('Failed to send verification email. Please try again.', 'danger')

    return render_template('customer/signup.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    pending_user = session.get('pending_user')
    if not pending_user:
        flash('Session expired. Please sign up again.', 'warning')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        # Verify OTP
        otp_record = otp_collection.find_one({
            'email': pending_user['email'],
            'otp': otp,
            'type': 'email',
            'used': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })

        if otp_record:
            # Mark OTP as used
            otp_collection.update_one(
                {'_id': otp_record['_id']},
                {'$set': {'used': True, 'used_at': datetime.utcnow()}}
            )

            # Create user
            user_id = users_collection.insert_one({
                'username': pending_user['username'],
                'password': pending_user['password'],
                'email': pending_user['email'],
                'phone': pending_user['phone'],
                'is_verified': True,
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }).inserted_id

            # Clear session
            session.pop('pending_user', None)

            # Create welcome notification
            notifications_collection.insert_one({
                'user_id': user_id,
                'title': 'Welcome to MySandwich!',
                'message': 'Thank you for signing up. Enjoy your shopping!',
                'read': False,
                'created_at': datetime.utcnow()
            })

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('customer/verify_otp.html')

@app.route('/resend_otp', methods=['POST'])
@login_required
def resend_otp():
    pending_user = session.get('pending_user')
    if not pending_user:
        flash('No pending verification found.', 'warning')
        return redirect(url_for('signup'))

    # Generate new OTP
    new_otp = generate_otp()
    otp_expiry = datetime.utcnow() + timedelta(minutes=15)

    # Invalidate previous OTPs
    otp_collection.update_many(
        {'email': pending_user['email'], 'type': 'email', 'used': False},
        {'$set': {'used': True}}
    )

    # Store new OTP
    otp_collection.insert_one({
        "username": pending_user['username'],
        "email": pending_user['email'],
        "otp": new_otp,
        "type": "email",
        "used": False,
        "expires_at": otp_expiry,
        "created_at": datetime.utcnow()
    })

    # Send email
    email_body = f"Your new verification code is: {new_otp}"
    if send_email(pending_user['email'], "New Verification Code", email_body):
        flash('New OTP sent to your email.', 'info')
    else:
        flash('Failed to resend OTP. Please try again.', 'danger')

    return redirect(url_for('verify_email'))



# MongoDB setup
db = client['ecommerce']
users_collection = db['users']
addresses_collection = db['addresses']
cards_collection = db['cards']
upis_collection = db['upis']
bank_accounts_collection = db['bank_accounts']
coupons_collection = db['coupons']
notifications_collection = db['notifications']
wishlist_collection = db['wishlist']
orders_collection = db['orders']
reviews_collection = db['reviews']
sessions_collection = db['sessions']
@app.route('/coupons')
def coupons():
    form = CouponForm()  # ✅ define form first
    now = datetime.now()
    coupons = list(coupons_collection.find().sort('expiry_date', 1))
    active_coupons = [c for c in coupons if c['expiry_date'] > now]
    expired_coupons = [c for c in coupons if c['expiry_date'] <= now]

    return render_template('customer/coupons.html',
    active_coupons=active_coupons,
    expired_coupons=expired_coupons,
    form=form  # 👈 pass the form
)


@app.route('/add_coupon', methods=['POST'])
def add_coupon():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user or not user.get('is_admin'):
        flash("Only admins can add coupons.")
        return redirect(url_for('coupons'))

    code = request.form.get('code', '').strip().upper()
    discount = request.form.get('discount', '').strip()
    expiry_date_str = request.form.get('expiry_date')

    try:
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
    except Exception:
        flash("Invalid expiry date.")
        return redirect(url_for('coupons'))

    existing = coupons_collection.find_one({'code': code})
    if existing:
        flash("Coupon already exists.")
    else:
        coupons_collection.insert_one({
            'code': code,
            'discount': discount,
            'expiry_date': expiry_date
        })
        flash("Coupon added successfully.")

    return redirect(url_for('coupons'))


@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    user = users_collection.find_one({'_id': user_id})
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    # Debugging addresses
    addresses = list(addresses_collection.find({'user_id': user_id}))

    user_data = {
        'user': user,
        'addresses': addresses,
        'cards': list(cards_collection.find({'user_id': user_id})),
        'upis': list(upis_collection.find({'user_id': user_id})),
        'bank_accounts': list(bank_accounts_collection.find({'user_id': user_id})),
        'coupons': list(coupons_collection.find({'user_id': user_id})),
        'notifications': list(notifications_collection.find({'user_id': user_id}).sort('created_at', -1)),
        'wishlist': list(wishlist_collection.find({'user_id': user_id})),
        'orders': list(orders_collection.find({'user_id': user_id}).sort('order_date', -1)),
        'reviews': list(reviews_collection.find({'user_id': user_id}).sort('created_at', -1)),
        'sessions': list(sessions_collection.find({'user_id': user_id, 'active': True}))
    }

    return render_template('customer/profile.html', **user_data)


@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    updates = {
        'name': request.form.get('name'),
        'gender': request.form.get('gender'),
        'email': request.form.get('email'),
        'birthdate': request.form.get('birthdate'),
        'bio': request.form.get('bio'),
        'updated_at': datetime.utcnow()
    }
    
    # Remove None values
    updates = {k: v for k, v in updates.items() if v is not None}
    
    users_collection.update_one(
        {'_id': user_id},
        {'$set': updates}
    )
    
    flash('Profile updated successfully', 'success')
    return redirect(url_for('account'))

@app.route('/add_address', methods=['POST'])
def add_address():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    address_id = request.form.get('address_id')
    
    address_data = {
        'user_id': user_id,
        'name': request.form.get('name'),
        'address_line1': request.form.get('address_line1'),
        'address_line2': request.form.get('address_line2'),
        'city': request.form.get('city'),
        'state': request.form.get('state'),
        'zip': request.form.get('zip'),
        'landmark': request.form.get('landmark'),
        'address_type': request.form.get('address_type'),
        'is_default': bool(request.form.get('make_default')),
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    if address_id:
        # Update existing address
        addresses_collection.update_one(
            {'_id': ObjectId(address_id), 'user_id': user_id},
            {'$set': address_data}
        )
        flash('Address updated successfully', 'success')
    else:
        # Insert new address
        addresses_collection.insert_one(address_data)
        flash('Address added successfully', 'success')
    
    # If this is set as default, update all other addresses
    if address_data['is_default']:
        addresses_collection.update_many(
            {'user_id': user_id, '_id': {'$ne': ObjectId(address_id) if address_id else {'$exists': True}}},
            {'$set': {'is_default': False}}
        )
    
    return redirect(url_for('account'))

@app.route('/set_default_address/<address_id>', methods=['POST'])
def set_default_address(address_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    # Set all addresses to not default first
    addresses_collection.update_many(
        {'user_id': user_id},
        {'$set': {'is_default': False}}
    )
    
    # Then set the selected one as default
    addresses_collection.update_one(
        {'_id': ObjectId(address_id), 'user_id': user_id},
        {'$set': {'is_default': True}}
    )
    
    flash('Default address updated', 'success')
    return redirect(url_for('account'))

@app.route('/delete_address/<address_id>', methods=['POST'])
def delete_address(address_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    addresses_collection.delete_one({'_id': ObjectId(address_id), 'user_id': user_id})
    
    flash('Address deleted', 'success')
    return redirect(url_for('account'))

@app.route('/get_address/<address_id>')
def get_address(address_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = ObjectId(session['user_id'])
    address = addresses_collection.find_one({'_id': ObjectId(address_id), 'user_id': user_id})
    
    if not address:
        return jsonify({'error': 'Address not found'}), 404
    
    # Convert ObjectId to string and datetime to string
    address['_id'] = str(address['_id'])
    if 'created_at' in address:
        address['created_at'] = address['created_at'].isoformat()
    if 'updated_at' in address:
        address['updated_at'] = address['updated_at'].isoformat()
    
    return jsonify(address)


@app.route('/add_card', methods=['POST'])
def add_card():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    card_data = {
        'user_id': user_id,
        'card_number': request.form.get('card_number'),
        'expiry': request.form.get('expiry'),
        'card_holder': request.form.get('card_holder'),
        'cvv': request.form.get('cvv'),
        'is_default': bool(request.form.get('make_default')),
        'created_at': datetime.utcnow()
    }
    
    # Determine card type based on first digit (simplified)
    first_digit = card_data['card_number'][0]
    if first_digit == '4':
        card_data['card_type'] = 'Visa'
    elif first_digit == '5':
        card_data['card_type'] = 'Mastercard'
    else:
        card_data['card_type'] = 'Other'
    
    cards_collection.insert_one(card_data)
    
    # If this is set as default, update all other cards
    if card_data['is_default']:
        cards_collection.update_many(
            {'user_id': user_id, '_id': {'$ne': card_data['_id']}},
            {'$set': {'is_default': False}}
        )
    
    flash('Card added successfully', 'success')
    return redirect(url_for('account'))

@app.route('/set_default_card/<card_id>', methods=['POST'])
def set_default_card(card_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    # Set all cards to not default first
    cards_collection.update_many(
        {'user_id': user_id},
        {'$set': {'is_default': False}}
    )
    
    # Then set the selected one as default
    cards_collection.update_one(
        {'_id': ObjectId(card_id), 'user_id': user_id},
        {'$set': {'is_default': True}}
    )
    
    flash('Default card updated', 'success')
    return redirect(url_for('account'))

@app.route('/delete_card/<card_id>', methods=['POST'])
def delete_card(card_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    cards_collection.delete_one({'_id': ObjectId(card_id), 'user_id': user_id})
    
    flash('Card removed', 'success')
    return redirect(url_for('account'))

@app.route('/add_upi', methods=['POST'])
def add_upi():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    upi_data = {
        'user_id': user_id,
        'upi_id': request.form.get('upi_id'),
        'is_default': bool(request.form.get('make_default')),
        'created_at': datetime.utcnow()
    }
    
    upis_collection.insert_one(upi_data)
    
    # If this is set as default, update all other UPIs
    if upi_data['is_default']:
        upis_collection.update_many(
            {'user_id': user_id, '_id': {'$ne': upi_data['_id']}},
            {'$set': {'is_default': False}}
        )
    
    flash('UPI ID added successfully', 'success')
    return redirect(url_for('account'))

@app.route('/set_default_upi/<upi_id>', methods=['POST'])
def set_default_upi(upi_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    # Set all UPIs to not default first
    upis_collection.update_many(
        {'user_id': user_id},
        {'$set': {'is_default': False}}
    )
    
    # Then set the selected one as default
    upis_collection.update_one(
        {'_id': ObjectId(upi_id), 'user_id': user_id},
        {'$set': {'is_default': True}}
    )
    
    flash('Default UPI updated', 'success')
    return redirect(url_for('account'))

@app.route('/delete_upi/<upi_id>', methods=['POST'])
def delete_upi(upi_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    upis_collection.delete_one({'_id': ObjectId(upi_id), 'user_id': user_id})
    
    flash('UPI ID removed', 'success')
    return redirect(url_for('account'))

@app.route('/add_bank_account', methods=['POST'])
def add_bank_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    bank_data = {
        'user_id': user_id,
        'account_holder': request.form.get('account_holder'),
        'account_number': request.form.get('account_number'),
        'ifsc': request.form.get('ifsc'),
        'bank_name': request.form.get('bank_name'),
        'is_default': bool(request.form.get('make_default')),
        'created_at': datetime.utcnow()
    }
    
    bank_accounts_collection.insert_one(bank_data)
    
    # If this is set as default, update all other bank accounts
    if bank_data['is_default']:
        bank_accounts_collection.update_many(
            {'user_id': user_id, '_id': {'$ne': bank_data['_id']}},
            {'$set': {'is_default': False}}
        )
    
    flash('Bank account added successfully', 'success')
    return redirect(url_for('account'))

@app.route('/set_default_bank/<bank_id>', methods=['POST'])
def set_default_bank(bank_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    
    # Set all bank accounts to not default first
    bank_accounts_collection.update_many(
        {'user_id': user_id},
        {'$set': {'is_default': False}}
    )
    
    # Then set the selected one as default
    bank_accounts_collection.update_one(
        {'_id': ObjectId(bank_id), 'user_id': user_id},
        {'$set': {'is_default': True}}
    )
    
    flash('Default bank account updated', 'success')
    return redirect(url_for('account'))

@app.route('/delete_bank_account/<bank_id>', methods=['POST'])
def delete_bank_account(bank_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    bank_accounts_collection.delete_one({'_id': ObjectId(bank_id), 'user_id': user_id})
    
    flash('Bank account removed', 'success')
    return redirect(url_for('account'))

@app.route('/add_wallet_balance', methods=['POST'])
def add_wallet_balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    amount = float(request.form.get('amount'))
    
    users_collection.update_one(
        {'_id': user_id},
        {'$inc': {'wallet_balance': amount}}
    )
    
    flash(f'${amount:.2f} added to your wallet', 'success')
    return redirect(url_for('account'))

@app.route('/mark_notifications_read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    notifications_collection.update_many(
        {'user_id': user_id},
        {'$set': {'read': True}}
    )
    
    flash('Notifications marked as read', 'success')
    return redirect(url_for('account'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = ObjectId(session['user_id'])
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    user = users_collection.find_one({'_id': user_id})
    
    if not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('account'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('account'))
    
    users_collection.update_one(
        {'_id': user_id},
        {'$set': {'password': generate_password_hash(new_password)}}
    )
    
    flash('Password changed successfully', 'success')
    return redirect(url_for('account'))

sessions_collection = db.sessions

@app.route('/revoke_session', methods=['POST'])
def revoke_session():
    # Get session_id from form data
    session_id = request.form.get('session_id')
    
    # Validate session_id presence
    if not session_id:
        return jsonify({'success': False, 'error': 'Missing session_id'}), 400
    
    # Validate ObjectId
    try:
        session_obj_id = ObjectId(session_id)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid session_id format'}), 400
    
    # Attempt to delete the session
    result = sessions_collection.delete_one({'_id': session_obj_id})
    
    if result.deleted_count == 1:
        return jsonify({'success': True, 'message': 'Session revoked successfully'})
    else:
        return jsonify({'success': False, 'error': 'Session not found'}), 404

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Mark session as inactive in database
        sessions_collection.update_one(
            {'session_id': session.get('session_id')},
            {'$set': {'active': False, 'ended_at': datetime.utcnow()}}
        )
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


@app.route('/verify_email_otp', methods=['POST'])
def verify_email_otp():
    otp = request.form.get('otp')
    email = session.get('email')  # email saved during signup or OTP send
    
    if not email:
        flash('Session expired or email not found. Please try again.')
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'email': email})
    
    if user and user.get('email_otp') == otp:
        users_collection.update_one({'email': email}, {'$set': {'email_verified': True}, '$unset': {'email_otp': ''}})
        flash('Email successfully verified.')
        return redirect(url_for('profile'))
    else:
        flash('Invalid OTP')
        return redirect(url_for('verify_otp_page'))
@app.route('/main')
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
    except Exception:
        flash("Invalid session ID. Please log in again.")
        return redirect(url_for('logout'))

    if not user:
        flash("User not found.")
        return redirect(url_for('logout'))

    payment_history = user.get("payment_history", [])
    payment_count = len(payment_history)

    def safe_float(value):
        try:
            return float(value)
        except Exception:
            return 0.0

    total_paid = sum(
        safe_float(p.get("price", p.get("amount", 0))) for p in payment_history
    )

    # Fetch sandwiches
    veg_items = list(veg_sandwiches_collection.find())
    nonveg_items = list(non_veg_sandwiches_collection.find())

    return render_template(
        "customer/main.html",
        username=user.get("username", "User"),
        payment_count=payment_count,
        total_paid=total_paid,
        veg_items=veg_items,
        nonveg_items=nonveg_items
    )

def serialize_all(item):
    item['_id'] = str(item['_id'])  # Convert ObjectId to string
    return item

@app.route('/get_sandwiches')
def get_sandwiches():
    veg_items = list(veg_sandwiches_collection.find())
    non_veg_items = list(non_veg_sandwiches_collection.find())
    
    # Serialize _id fields
    veg_items = [serialize_all(item) for item in veg_items]
    non_veg_items = [serialize_all(item) for item in non_veg_items]

    data = {
        'veg': veg_items,
        'non_veg': non_veg_items
    }

    return Response(json.dumps(data), mimetype='application/json')

@app.route('/view_cart')
def view_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])

    cart_items = list(cart_collection.find({'user_id': user_id}))
    saved_items = list(save_later_collection.find({'user_id': user_id}))

    return render_template('customer/cart.html',
                           cart_items=cart_items,
                           saved_items=saved_items)




@app.route('/move_to_wishlist/<item_name>', methods=['POST'])
def move_to_wishlist(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])

    cart_item = cart_collection.find_one({'user_id': user_id, 'name': item_name})
    if not cart_item:
        return redirect(url_for('view_cart'))

    # Remove from cart
    cart_collection.delete_one({'_id': cart_item['_id']})

    # Insert to wishlist if not already there
    existing_wishlist_item = wishlist_collection.find_one({'user_id': user_id, 'name': item_name})
    if not existing_wishlist_item:
        wishlist_collection.insert_one({
            'user_id': user_id,
            'name': cart_item['name'],
            'price': cart_item['price'],
            'quantity': cart_item.get('quantity', 1),
            'added_at': datetime.utcnow()
        })

    return redirect(url_for('view_cart'))



@app.route('/wishlist')
def wishlist():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    wishlist_items = list(wishlist_collection.find({'user_id': user_id}))
    return render_template('customer/wishlist.html', wishlist_items=wishlist_items)
@app.route('/add_wishlist_to_cart/<item_name>', methods=['POST'])
def add_wishlist_to_cart(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    wishlist_item = wishlist_collection.find_one({'user_id': user_id, 'name': item_name})
    if not wishlist_item:
        return redirect(url_for('wishlist'))

    # Remove from wishlist
    wishlist_collection.delete_one({'_id': wishlist_item['_id']})

    # Add to cart
    existing_cart_item = cart_collection.find_one({'user_id': user_id, 'name': item_name})
    if existing_cart_item:
        new_quantity = existing_cart_item.get('quantity', 1) + wishlist_item.get('quantity', 1)
        cart_collection.update_one({'_id': existing_cart_item['_id']}, {'$set': {'quantity': new_quantity}})
    else:
        cart_collection.insert_one({
            'user_id': user_id,
            'name': wishlist_item['name'],
            'price': wishlist_item['price'],
            'quantity': wishlist_item.get('quantity', 1),
            'added_at': datetime.utcnow()
        })

    return redirect(url_for('wishlist'))

@app.route('/remove_from_wishlist/<item_name>', methods=['POST'])
def remove_from_wishlist(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    wishlist_collection.delete_one({'user_id': user_id, 'name': item_name})
    return redirect(url_for('wishlist'))


# Save for Later - move item from cart to saved collection
@app.route('/save_for_later/<item_name>', methods=['POST'])
def save_for_later(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])

    cart_item = cart_collection.find_one({'user_id': user_id, 'name': item_name})
    if not cart_item:
        return redirect(url_for('view_cart'))

    # Check if already saved
    saved_item = save_later_collection.find_one({'user_id': user_id, 'name': item_name})

    if saved_item:
        new_quantity = saved_item.get('quantity', 1) + cart_item.get('quantity', 1)
        save_later_collection.update_one(
            {'_id': saved_item['_id']},
            {'$set': {'quantity': new_quantity}}
        )
    else:
        save_later_collection.insert_one({
            'user_id': user_id,
            'name': cart_item['name'],
            'price': cart_item['price'],
            'quantity': cart_item['quantity'],
            # Include other fields as needed (image, category, etc.)
        })

    # Remove from cart after saving
    cart_collection.delete_one({'_id': cart_item['_id']})
    return redirect(url_for('view_cart'))


# Remove item from saved collection
@app.route('/remove_from_saved/<item_name>', methods=['POST'])
def remove_from_saved(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    save_later_collection.delete_one({'user_id': user_id, 'name': item_name})
    return redirect(url_for('view_cart'))


# Add back to cart from saved
@app.route('/add_back_to_cart/<item_name>', methods=['POST'])
def add_back_to_cart(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])

    saved_item = save_later_collection.find_one({'user_id': user_id, 'name': item_name})
    if not saved_item:
        return redirect(url_for('view_cart'))

    cart_item = cart_collection.find_one({'user_id': user_id, 'name': item_name})

    if cart_item:
        new_quantity = cart_item.get('quantity', 1) + saved_item.get('quantity', 1)
        cart_collection.update_one(
            {'_id': cart_item['_id']},
            {'$set': {'quantity': new_quantity}}
        )
    else:
        cart_collection.insert_one({
            'user_id': user_id,
            'name': saved_item['name'],
            'price': saved_item['price'],
            'quantity': saved_item['quantity'],
            # Include any other fields like image, type, etc.
        })

    save_later_collection.delete_one({'_id': saved_item['_id']})
    return redirect(url_for('view_cart'))


# Update quantity in cart
@app.route('/update_quantity/<item_name>', methods=['POST'])
def update_quantity(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = ObjectId(session['user_id'])

    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        quantity = 1

    cart_collection.update_one(
        {'user_id': user_id, 'name': item_name},
        {'$set': {'quantity': quantity}}
    )
    return redirect(url_for('view_cart'))

# Remove from cart
@app.route('/remove_from_cart/<item_name>', methods=['POST'])
def remove_from_cart(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = ObjectId(session['user_id'])

    cart_collection.delete_one({'user_id': user_id, 'name': item_name})
    return redirect(url_for('view_cart'))

users_collection.create_index([("email", ASCENDING)], unique=True)

# --- HELPERS ---

def get_user_profile(user_id):
    user = users_collection.find_one({"_id": user_id})
    if not user:
        return {"email": "", "default_address": ""}
    return {
        "email": user.get("email", ""),
        "default_address": user.get("default_address", "")
    }

def get_order_items(user_id):
    order = orders_collection.find_one({"user_id": user_id, "status": "in_progress"})
    return order.get("items", []) if order else []

def update_order_item_quantity(user_id, item_id, new_quantity):
    order = orders_collection.find_one({"user_id": user_id, "status": "in_progress"})
    if not order:
        return False

    updated = False
    for item in order["items"]:
        if item["id"] == item_id:
            item["quantity"] = new_quantity
            updated = True
            break

    if updated:
        orders_collection.update_one(
            {"_id": order["_id"]},
            {"$set": {"items": order["items"]}}
        )
    return updated



@app.route('/remove_item', methods=['POST'])
def remove_item():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Not logged in"}), 403

    user_id = ObjectId(session['user_id'])
    item_id = int(request.form.get('item_id'))

    order = orders_collection.find_one({"user_id": user_id, "status": "in_progress"})
    if not order:
        return jsonify({"status": "error", "message": "Order not found"}), 404

    updated_items = [item for item in order['items'] if item['id'] != item_id]
    result = orders_collection.update_one(
        {"_id": order["_id"]},
        {"$set": {"items": updated_items}}
    )

    if result.modified_count:
        return jsonify({"status": "success", "message": "Item removed"})
    return jsonify({"status": "error", "message": "Update failed"}), 500

@app.route('/save_address', methods=['POST'])
def save_address():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    new_address = request.form.get('address')
    if new_address and new_address.strip():
        user_id = ObjectId(session['user_id'])
        result = users_collection.update_one(
            {"_id": user_id},
            {"$set": {"default_address": new_address.strip()}}
        )
        if result.modified_count:
            return jsonify({"status": "success", "address": new_address.strip()})
    return jsonify({"status": "error", "message": "Invalid address provided."}), 400

# Collections for sandwiches
veg_sandwiches_collection = db.veg_sandwiches

@app.route('/get_default_address', methods=['GET'])
def get_default_address():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    user_id = ObjectId(session['user_id'])
    address = addresses_collection.find_one({'user_id': user_id, 'is_default': True})

    if address:
        return jsonify({
            'fullName': address.get('fullName', ''),
            'street': address.get('street', ''),
            'city': address.get('city', ''),
            'state': address.get('state', ''),
            'zip': address.get('zip', ''),
            'country': address.get('country', ''),
            'phone': address.get('phone', ''),
        })
    else:
        return jsonify({'error': 'No default address found'}), 404

@app.route('/buy_now/<item_name>', methods=['POST'])
def buy_now(item_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    quantity = int(request.form.get('quantity', 1))

    item = veg_sandwiches_collection.find_one({'name': item_name}) or \
           non_veg_sandwiches_collection.find_one({'name': item_name})

    if not item:
        flash("Item not found.", "error")
        return redirect(url_for('main'))

    checkout_items = [{
        'name': item['name'],
        'price': item['price'],
        'quantity': quantity,
        'image_url': item.get('image_url', '')
    }]

    session['checkout_items'] = checkout_items
    session['checkout_total'] = item['price'] * quantity

    return redirect(url_for('checkout'))

@app.route('/buy_all', methods=['POST'])
def buy_all():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    cart_items = list(cart_collection.find({'user_id': user_id}))

    if not cart_items:
        flash("Your cart is empty.", "error")
        return redirect(url_for('view_cart'))

    checkout_items = []
    total = 0

    for item in cart_items:
        quantity = item.get('quantity', 1)
        price = item.get('price', 0)
        subtotal = price * quantity
        total += subtotal

        checkout_items.append({
            'name': item['name'],
            'price': price,
            'quantity': quantity,
            'image_url': item.get('image_url', '')
        })

    session['checkout_items'] = checkout_items
    session['checkout_total'] = total

    return redirect(url_for('checkout'))
from datetime import datetime


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in to add items to your cart.'})

    user_id = ObjectId(session['user_id'])
    name = request.json.get('name')
    price = request.json.get('price')
    quantity = int(request.json.get('quantity', 1))  # Ensure quantity is int

    # Check if item exists in veg or non-veg
    item = veg_sandwiches_collection.find_one({'name': name}) or \
           non_veg_sandwiches_collection.find_one({'name': name})

    if not item:
        return jsonify({'success': False, 'message': 'Item not found.'})

    # Check if item already exists in user's cart
    existing_item = cart_collection.find_one({'user_id': user_id, 'name': name})

    if existing_item:
        # Update quantity
        new_quantity = existing_item['quantity'] + quantity
        cart_collection.update_one(
            {'_id': existing_item['_id']},
            {'$set': {'quantity': new_quantity}}
        )
        message = f"Quantity updated to {new_quantity}."
    else:
        # Add new item to cart
        cart_item = {
            'user_id': user_id,
            'name': name,
            'price': price,
            'quantity': quantity,
            'image_url': item.get('image_url', '')
        }
        cart_collection.insert_one(cart_item)
        message = 'Item added to cart.'

    return jsonify({'success': True, 'message': message})


@app.route('/pay_add_card', methods=['POST'])
def pay_add_card():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    card_data = {
        'user_id': ObjectId(session['user_id']),
        'card_holder': request.form['card_holder'],
        'card_number': request.form['card_number'],
        'expiry': request.form['expiry'],
        'cvv': request.form['cvv']
    }
    cards_collection.insert_one(card_data)
    return redirect(url_for('payment'))


@app.route('/pay_add_upi', methods=['POST'])
def pay_add_upi():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    upi_data = {
        'user_id': ObjectId(session['user_id']),
        'upi_id': request.form['upi_id']
    }
    upis_collection.insert_one(upi_data)
    return redirect(url_for('payment'))


@app.route('/pay_add_bank_account', methods=['POST'])
def pay_add_bank_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bank_data = {
        'user_id': ObjectId(session['user_id']),
        'account_holder': request.form['account_holder'],
        'account_number': request.form['account_number'],
        'ifsc_code': request.form['ifsc_code']
    }
    bank_accounts_collection.insert_one(bank_data)
    return redirect(url_for('payment'))

# Collections
users_collection = db['users']
addresses_collection = db['addresses']
cards_collection = db['cards']
upis_collection = db['upis']
bank_accounts_collection = db['bank_accounts']
orders_collection = db['orders']

from flask import request, flash

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])

    default_address = addresses_collection.find_one({
        'user_id': user_id,
        'is_default': True
    }) or {}

    checkout_items = session.get('checkout_items', [])

    for item in checkout_items:
        item.setdefault('order_date', datetime.utcnow())

    checkout_total = sum(item.get('price', 0) * item.get('quantity', 0) for item in checkout_items)

    applied_coupon = None
    discount_amount = 0

    # Handle coupon form
    if request.method == 'POST':
        coupon_code = request.form.get('coupon_code', '').strip().upper()

        if coupon_code:
            coupon = coupons_collection.find_one({'code': coupon_code})
            if not coupon:
                flash("Invalid coupon code.", 'error')
            elif datetime.utcnow() > coupon.get('expiry_date', datetime.utcnow()):
                flash("This coupon has expired.", 'error')
            else:
                applied_coupon = coupon
                discount_percent = coupon.get('discount', 0)
                discount_amount = (checkout_total * discount_percent) / 100
                checkout_total -= discount_amount
                flash(f"Coupon '{coupon_code}' applied. You saved ₹{discount_amount:.2f}!", 'success')
        else:
            flash("Please enter a coupon code.", 'error')

    # Create order if not already in progress
    in_progress_order = orders_collection.find_one({'user_id': user_id, 'status': 'in_progress'})
    if not in_progress_order:
        order_id = orders_collection.insert_one({
            'user_id': user_id,
            'items': checkout_items,
            'total_amount': checkout_total,
            'status': 'in_progress',
            'order_date': datetime.utcnow(),
            'address': default_address,
            'applied_coupon': applied_coupon['code'] if applied_coupon else None,
            'discount_amount': round(discount_amount, 2)
        }).inserted_id
        session['order_id'] = str(order_id)
    else:
        session['order_id'] = str(in_progress_order['_id'])

    return render_template(
        'customer/checkout.html',
        checkout_items=checkout_items,
        checkout_total=round(checkout_total, 2),
        default_address=default_address,
        applied_coupon=applied_coupon,
        discount_amount=round(discount_amount, 2)
    )


@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    order_id = session.get('order_id')
    if not order_id:
        flash('No active order found.', 'error')
        return redirect(url_for('checkout'))

    order = orders_collection.find_one({'_id': ObjectId(order_id), 'user_id': user_id, 'status': 'in_progress'})
    if not order:
        flash('Invalid order.', 'error')
        return redirect(url_for('checkout'))

    checkout_items = session.get('checkout_items', [])
    quantities = request.form.to_dict(flat=False).get('quantities[]') or []
    if not quantities:
        quantities = [request.form.get(f'quantities[{i}]') for i in range(len(checkout_items))]

    updated_items = []
    total_amount = 0
    for i, item in enumerate(checkout_items):
        qty = int(quantities[i])
        item['quantity'] = qty
        total_amount += item['price'] * qty
        updated_items.append(item)

    address_type = request.form.get('address_type')
    if address_type == 'default':
        user_doc = users_collection.find_one({'_id': user_id})
        shipping_address = user_doc.get('default_address')
    else:
        shipping_address = {
            'full_name': request.form.get('fullName'),
            'street': request.form.get('street'),
            'city': request.form.get('city'),
            'state': request.form.get('state'),
            'zip': request.form.get('zip'),
            'country': request.form.get('country'),
            'phone': request.form.get('phone')
        }

    payment_method = request.form.get('payment_method')
    if not payment_method:
        flash('Payment method not selected.', 'error')
        return redirect(url_for('checkout'))

    orders_collection.update_one(
        {'_id': ObjectId(order_id)},
        {
            "$set": {
                'items': updated_items,
                'total_amount': total_amount,
                'address': shipping_address,
                'payment_method': payment_method
            }
        }
    )

    session['total_amount'] = total_amount
    session['payment_method'] = payment_method

    if payment_method.lower() == 'cod':
        return redirect(url_for('cod_confirmation', amount=total_amount))
    else:
        return redirect(url_for('payment'))

@app.route('/pay_process_payment', methods=['POST'])
def pay_process_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    order_id = session.get('order_id')
    payment_type = request.form.get('payment_type')
    total_amount = session.get('total_amount')

    if not order_id:
        flash("No active order found.", 'error')
        return redirect(url_for('checkout'))

    result = orders_collection.update_one(
        {"_id": ObjectId(order_id), "user_id": user_id},
        {
            "$set": {
                "status": "placed",
                "payment_type": payment_type,
                "order_date": datetime.utcnow(),
                "delivery_date": datetime.utcnow() + timedelta(days=2)
            }
        }
    )

    if result.modified_count:
        users_collection.update_one(
            {'_id': user_id},
            {'$push': {
                'payment_history': {
                    'order_id': order_id,
                    'amount': total_amount,
                    'method': payment_type,
                    'date': datetime.utcnow()
                }
            }}
        )
        flash("Payment successful and order placed!", 'success')
        return redirect(url_for('payment_success'))
    else:
        flash("Order update failed.", 'error')
        return redirect(url_for('checkout'))

@app.route('/payment', methods=['POST'])
def payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = ObjectId(session['user_id'])
    user = users_collection.find_one({'_id': user_id})

    cards = list(cards_collection.find({'user_id': user_id}))
    upis = list(upis_collection.find({'user_id': user_id}))
    banks = list(bank_accounts_collection.find({'user_id': user_id}))
    wallet_balance = user.get('wallet_balance', 0.0)

    return render_template('customer/payment.html', cards=cards, upis=upis, banks=banks, wallet_balance=wallet_balance)

@app.route('/payment_success')
def payment_success():
    return render_template('customer/payment_success.html') 

from flask import redirect, url_for, flash

from flask import redirect, url_for, flash

@app.route('/cod-confirmation', methods=['GET'])
def cod_confirmation():
    try:
        # Get data from session instead of form
        total_amount = session.get('total_amount')
        order_id = session.get('order_id')
        user_id = ObjectId(session['user_id'])
        
        if not all([total_amount, order_id, user_id]):
            flash('Missing order information', 'error')
            return redirect(url_for('checkout'))

        # Update the existing order in database
        orders_collection.update_one(
            {'_id': ObjectId(order_id), 'user_id': user_id},
            {
                "$set": {
                    'status': 'confirmed',
                    'payment_status': 'pending',
                    'confirmed_date': datetime.now()
                }
            }
        )

        # Clear session data
        session.pop('order_id', None)
        session.pop('checkout_items', None)
        session.pop('total_amount', None)

        # Redirect to orders page with success message
        flash('Your COD order has been placed successfully!', 'success')
        return redirect(url_for('orders'))  # Assuming you have an orders route

    except Exception as e:
        flash(f'Order confirmation failed: {str(e)}', 'error')
        return redirect(url_for('checkout'))
#<-----------------------------------------admin panel---------------------------------------->

# Create default admin if not exists
default_admin_username = 'admin'
default_admin_password = 'admin123'  # CHANGE this in production
existing_admin = admins_collections.find_one({'username': default_admin_username})

if not existing_admin:
    hashed_password = generate_password_hash(default_admin_password)
    admins_collections.insert_one({
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
existing_manager = admins_collections.find_one({'username': default_manager_username})

if not existing_manager:
    hashed_password = generate_password_hash(default_manager_password)
    admins_collections.insert_one({
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

        admin = admins_collections.find_one({'username': username})
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
def admin_dashboard():
    # Basic counts for all roles
    veg_count = veg_sandwiches_collection.count_documents({})
    non_veg_count = non_veg_sandwiches_collection.count_documents({})
    total_orders = orders_collection.count_documents({})
    
    # Determine role from session
    role = session.get('admin_role')  # 'admin' or 'manager'
    is_admin = role == 'admin'

    # Only show total users to admins
    total_users = None
    if is_admin:
        total_users = users_collection.count_documents({'role': {'$ne': 'manager'}})  # Exclude managers from count

    # Recent orders (for both roles)
    recent_orders = list(orders_collection.find().sort('order_date', -1).limit(10))

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
        result = list(orders_collection.aggregate(pipeline))
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
def view_users():
    if session.get('admin_role') != 'admin':
        abort(403)
    all_users = list(users_collection.find({}))
    return render_template('admin/users.html', users=all_users)

@app.route('/admin/users/delete/<user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('admin_role') != 'admin':
        abort(403)
    users_collection.delete_one({'_id': ObjectId(user_id)})
    return redirect(url_for('view_users'))



veg_sandwiches = db['veg_sandwiches']
non_veg_sandwiches = db['non_veg_sandwiches']

# ---------------- Admin Sandwich Management ----------------
@app.route('/admin/sandwiches')
def admin_sandwiches():
    if 'admin_username' not in session:
        flash("Please login as admin.")
        return redirect('/admin/login')
    veg_items = list(veg_sandwiches.find())
    nonveg_items = list(non_veg_sandwiches.find())
    return render_template('admin/admin_sandwiches.html', veg_items=veg_items, nonveg_items=nonveg_items)

from werkzeug.utils import secure_filename
import os
from flask import request, redirect, session, flash

@app.route('/admin/add_sandwich', methods=['POST'])
def add_sandwich():
    if 'admin_username' not in session:
        return redirect('/admin/login')
    
    name = request.form['name']
    category = request.form['category']
    price = float(request.form['price'])
    description = request.form['description']

    image_file = request.files['image']
    if image_file and image_file.filename != '':
        filename = secure_filename(image_file.filename)
        image_path = os.path.join('static/uploads', filename)
        image_file.save(image_path)
        image_url = '/' + image_path.replace("\\", "/")  # Make it browser-friendly
    else:
        flash('Image upload failed.', 'error')
        return redirect('/admin/sandwiches')

    # Now create the sandwich object using image_url after saving the file
    sandwich = {
        'name': name,
        'category': category,
        'price': price,
        'description': description,
        'image_url': image_url
    }

    # Insert into correct collection
    if category == 'veg':
        veg_sandwiches.insert_one(sandwich)
    else:
        non_veg_sandwiches.insert_one(sandwich)
    
    flash(f"{category.capitalize()} sandwich added successfully.")
    return redirect('/admin/sandwiches')


@app.route('/admin/edit_sandwich/<category>/<sandwich_id>', methods=['POST'])
def edit_sandwich(category, sandwich_id):
    if 'admin_username' not in session:
        return redirect('/admin/login')

    updated_data = {
        'name': request.form['name'],
        'price': float(request.form['price']),
        'description': request.form['description'],
        'image_url': request.form['image_url']
    }

    collection = veg_sandwiches if category == 'veg' else non_veg_sandwiches
    collection.update_one({'_id': ObjectId(sandwich_id)}, {'$set': updated_data})
    
    flash(f"{category.capitalize()} sandwich updated successfully.")
    return redirect('/admin/sandwiches')

@app.route('/admin/delete_sandwich/<category>/<sandwich_id>')
def delete_sandwich(category, sandwich_id):
    if 'admin_username' not in session:
        return redirect('/admin/login')

    collection = veg_sandwiches if category == 'veg' else non_veg_sandwiches
    collection.delete_one({'_id': ObjectId(sandwich_id)})

    flash(f"{category.capitalize()} sandwich deleted.")
    return redirect('/admin/sandwiches')

class CouponForm(FlaskForm):
    code = StringField('Coupon Code', validators=[DataRequired()])
    discount = IntegerField('Discount (%)', validators=[NumberRange(min=1, max=100)])
    expiry_date = DateField('Expiry Date', format='%Y-%m-%d', validators=[DataRequired()])

@app.route('/admin/coupons', methods=['GET', 'POST'])
def admin_coupons():
    if 'admin_username' not in session:
        return redirect(url_for('login'))

    is_admin = session.get('is_admin', False)
    form = CouponForm()

    if request.method == 'POST' and form.validate_on_submit():
        code = form.code.data.strip().upper()

        # Prevent duplicates
        if coupons_collection.find_one({'code': code}):
            flash('Coupon already exists.', 'error')
        else:
            coupon_data = {
                'code': code,
                'created_by': session['admin_username'],
                'discount': form.discount.data,
                'expiry_date': datetime.combine(form.expiry_date.data, datetime.min.time())
            }
            coupons_collection.insert_one(coupon_data)
            flash('Coupon created successfully!', 'success')
        return redirect(url_for('admin_coupons'))

    all_coupons = list(coupons_collection.find().sort('expiry_date', 1))
    now = datetime.now()
    active_coupons = [c for c in all_coupons if c.get('expiry_date') and c['expiry_date'] > now]
    expired_coupons = [c for c in all_coupons if c.get('expiry_date') and c['expiry_date'] <= now]

    return render_template('admin/admin_coupons.html',
                           form=form,
                           is_admin=is_admin,
                           active_coupons=active_coupons,
                           expired_coupons=expired_coupons)

@app.route('/admin/coupons/delete/<code>', methods=['POST'])
def delete_coupon(code):
    if 'admin_username' not in session:
        return redirect(url_for('login'))

    coupons_collection.delete_one({'code': code})
    flash(f"Coupon {code} deleted.", 'success')
    return redirect(url_for('admin_coupons'))
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, DateField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange

class CouponForm(FlaskForm):
    code = StringField('Coupon Code', validators=[DataRequired(), Length(min=3, max=20)])
    discount = IntegerField('Discount (%)', validators=[NumberRange(min=0, max=100)], default=0)
    expiry_date = DateField('Expiry Date', validators=[DataRequired()])
    submit = SubmitField('Add Coupon')  # ✅ THIS IS MISSING

# ---------------- Run the App ----------------

if __name__ == '__main__':
    app.run(debug=True,port=4001)
