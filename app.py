from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "Sasank0099@"  # Use environment variables in production

# MongoDB setup
mongo_uri = "mongodb+srv://Sasank0099:Vv6MtscDKXHhn1QR@cluster0.68ku4.mongodb.net/"
client = MongoClient(mongo_uri)
db = client["testdb"]
users = db["users"]

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = generate_password_hash(request.form['password'])
        email = request.form['email'].strip()
        phone = request.form['phone'].strip()

        if users.find_one({"username": username}):
            return "❌ Username already exists!"

        users.insert_one({
            "username": username,
            "password": password,
            "email": email,
            "phone": phone,
            "cart": [],
            "saved": [],
            "purchase": [],
            "payment_history": [],
            "wishlist": [],
            "addresses": []
        })
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = users.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('main'))
        return "❌ Invalid credentials!"
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/main')
def main():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users.find_one({"username": session['username']})
    if not user:
        return redirect(url_for('login'))

    payment_history = user.get("payment_history", [])
    payment_count = len(payment_history)

    def safe_float(value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    total_paid = sum(safe_float(p.get("price", p.get("amount", 0))) for p in payment_history)

    return render_template("main.html",
                           username=user["username"],
                           payment_count=payment_count,
                           total_paid=total_paid)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'username' not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401

    data = request.get_json()
    name = data.get('name')
    price = data.get('price')

    if not name or price is None:
        return jsonify({"success": False, "message": "Invalid item data"}), 400

    username = session['username']
    user = users.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    cart_item = {"name": name, "price": price, "added_at": datetime.utcnow()}
    users.update_one({"username": username}, {"$push": {"cart": cart_item}})
    return jsonify({"success": True})

@app.route('/view_cart')
def view_cart():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users.find_one({'username': session['username']})
    cart_items = user.get('cart', [])
    saved_items = user.get('saved', [])
    return render_template('cart.html', cart_items=cart_items, saved_items=saved_items)

@app.route('/save_for_later/<item_name>', methods=['POST'])
def save_for_later(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({'username': username})
    cart_items = user.get('cart', [])

    item_to_save = next((item for item in cart_items if item['name'] == item_name), None)

    if item_to_save:
        users.update_one({'username': username}, {'$pull': {'cart': {'name': item_name}}})
        users.update_one({'username': username}, {'$push': {'saved': item_to_save}})

    return redirect(url_for('view_cart'))

@app.route('/remove_from_cart/<item_name>', methods=['POST'])
def remove_from_cart(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    users.update_one(
        {'username': session['username']},
        {'$pull': {'cart': {'name': item_name}}}
    )
    return redirect(url_for('view_cart'))

@app.route('/add_back_to_cart/<item_name>', methods=['POST'])
def add_back_to_cart(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({'username': username})
    saved_items = user.get('saved', [])

    item_to_move = next((item for item in saved_items if item['name'] == item_name), None)

    if item_to_move:
        users.update_one({'username': username}, {'$pull': {'saved': {'name': item_name}}})
        users.update_one({'username': username}, {'$push': {'cart': item_to_move}})

    return redirect(url_for('view_cart'))

@app.route('/remove_from_saved/<item_name>', methods=['POST'])
def remove_from_saved(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    users.update_one(
        {'username': session['username']},
        {'$pull': {'saved': {'name': item_name}}}
    )
    return redirect(url_for('view_cart'))

@app.route('/add_to_wishlist/<item_name>', methods=['POST'])
def add_to_wishlist(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({'username': username})
    cart_items = user.get('cart', [])
    item_to_move = next((item for item in cart_items if item['name'] == item_name), None)

    if item_to_move:
        users.update_one({'username': username}, {'$pull': {'cart': {'name': item_name}}})
        users.update_one({'username': username}, {'$push': {'wishlist': item_to_move}})
    
    return redirect(url_for('view_cart'))

@app.route('/wishlist')
def wishlist():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({'username': username})
    wishlist_items = user.get('wishlist', [])
    return render_template('wishlist.html', wishlist_items=wishlist_items)

@app.route('/add_wishlist_to_cart/<item_name>', methods=['POST'])
def add_wishlist_to_cart(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({'username': username})
    wishlist_items = user.get('wishlist', [])
    item_to_move = next((item for item in wishlist_items if item['name'] == item_name), None)

    if item_to_move:
        users.update_one({'username': username}, {'$pull': {'wishlist': {'name': item_name}}})
        users.update_one({'username': username}, {'$push': {'cart': item_to_move}})
    
    return redirect(url_for('wishlist'))

@app.route('/remove_from_wishlist/<item_name>', methods=['POST'])
def remove_from_wishlist(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    users.update_one({'username': username}, {'$pull': {'wishlist': {'name': item_name}}})
    
    return redirect(url_for('wishlist'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users.find_one({'username': session['username']})

    total_orders = len(user.get('purchase', []))
    total_spent = sum(order['total'] for order in user.get('purchase', []))
    
    sandwich_counts = {}
    for order in user.get('purchase', []):
        for item in order['items']:
            sandwich_counts[item['name']] = sandwich_counts.get(item['name'], 0) + 1
    favorite_sandwich = max(sandwich_counts, key=sandwich_counts.get) if sandwich_counts else "None"

    return render_template("profile.html",
                           user=user,
                           total_orders=total_orders,
                           total_spent=total_spent,
                           favorite_sandwich=favorite_sandwich)
@app.route('/buy_now/<item_name>', methods=['POST'])
def buy_now(item_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({"username": username})
    cart_items = user.get("cart", [])

    item_to_buy = next((item for item in cart_items if item["name"] == item_name), None)

    if item_to_buy:
        session['buy_now_item'] = item_to_buy
        return redirect(url_for('my_orders'))
    
    return "Item not found in cart", 404

@app.route('/my_orders')
@app.route('/my_orders')
@app.route('/my_orders')
def my_orders():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = users.find_one({"username": session["username"]})
    buy_now_item = session.get('buy_now_item')

    if buy_now_item:
        cart_items = [buy_now_item]
    else:
        cart_items = user.get("cart", [])

    def parse_price(p):
        try:
            return float(str(p).replace('$', '').replace('₹', '').strip())
        except:
            return 0.0

    total_items = sum(int(item.get("quantity", 1)) for item in cart_items)
    total_amount = sum(parse_price(item.get("price", 0)) * int(item.get("quantity", 1)) for item in cart_items)

    return render_template("my_orders.html",
                           total_items=total_items,
                           total_amount=round(total_amount, 2),
                           cart_items=cart_items,
                           buy_now=bool(buy_now_item))


@app.route('/confirm_order', methods=['POST'])
def confirm_order():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = users.find_one({"username": username})

    name = request.form.get('name')
    phone = request.form.get('phone')
    address = request.form.get('address')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    payment_mode = request.form.get('payment_mode')

    buy_now_item = session.pop('buy_now_item', None)
    if buy_now_item:
        cart_items = [buy_now_item]
    else:
        cart_items = user.get('cart', [])

    if not cart_items:
        return "Cart is empty", 400

    def parse_price(p):
        try:
            return float(str(p).replace('$', '').replace('₹', '').strip())
        except:
            return 0.0

    total = sum(parse_price(item.get("price", 0)) * int(item.get("quantity", 1)) for item in cart_items)

    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    order_doc = {
        "items": cart_items,
        "total_amount": total,
        "address": address,
        "phone": phone,
        "location": {"lat": latitude, "lon": longitude},
        "payment_mode": payment_mode,
        "timestamp": now,
        "name": name,
        "username": username
    }

    users.update_one(
        {"username": username},
        {
            "$push": {"purchase": order_doc, "payment_history": {"price": total, "timestamp": now, "payment_mode": payment_mode}},
            "$set": {"cart": []}
        }
    )

    return render_template("payment_success.html")

@app.route('/place_order', methods=['POST'])
def place_order():
    if 'username' not in session:
        return jsonify({"success": False, "message": "User not logged in"})

    data = request.json
    name = data.get('name')
    price = data.get('price')
    quantity = int(data.get('quantity'))

    # Clean price to float
    price_float = float(price.replace('$', ''))
    total_price = round(price_float * quantity, 2)

    order_item = {
        "name": name,
        "price": f"${price_float:.2f}",
        "quantity": quantity,
        "total_price": f"${total_price:.2f}"
    }

    # Save this to session so /my_orders knows it's a 'Buy Now'
    session['buy_now_item'] = order_item

    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(debug=True, port=4001)
