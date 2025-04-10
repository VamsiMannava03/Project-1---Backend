#Import the needed Flask modules
#Bcrypt is for the password hashing making it more secure
from flask import Flask, request, jsonify, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_jwt_extended import *
from datetime import datetime, timedelta
from functools import wraps  
import jwt
import re

#Initialize the Flask app
app = Flask(__name__)

#The secret key for the session cookies
app.config['SECRET_KEY'] = 'CPSC449'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://inventory_user:Inventory%40123@localhost/inventory_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Session will be saved to the file system
app.config['SESSION_TYPE'] = 'filesystem'

# session experation
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)


#Initialize 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# Email validation using regex
def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

# Password strength validation
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

#This is how the user is structured in the database with these fields
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(100), default='user')

# This is to verify the password agaist the hashed password 
    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

#This is how the inventory item is structured in the database with these fields
class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
      
# Create tables before the app starts handling requests
with app.app_context():
    db.create_all()

# User Registration (2nd bulletpoint in #1) We need to allow new users to register by giving a username,
# password and an email.

#User Registration (define the route)
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Validate input fields
    if not username or not password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400

    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    if not is_valid_password(password):
        return jsonify({
            "error": "Password must be at least 8 characters long and include an uppercase letter, a number, and a special character."
        }), 400

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create user
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# User login (1st bulletpoint in #1) We need to make sure it allows a user to login by taking a username
# and password. We also need to use sessions and cookies to track the login states.

#User login (define the route)
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

#Validate Inputs are there (username and password)
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

#Look for user by username
    user = User.query.filter_by(username=username).first()

#Check the user info entered
    if not user or not user.verify_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

#Create the session it will store the user ID and username
    session['user_id'] = user.id
    session['username'] = user.username
    session.permanent =  True

#Set the sessoion cookie
    response = jsonify({"message": "Login successful", "username": user.username})
    response.set_cookie('session', str(session['user_id']), httponly=True)
    return response, 200

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

#Validate Inputs are there (username and password)
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

#Look for user by username
    user = User.query.filter_by(username=username).first()

#Check the user info entered
    if not user or not user.verify_password(password) or user.role != 'admin':
        return jsonify({"error": "Invalid username or password or user is not admin"}), 401

#Add JWT
  # Generate JWT token valid for 30 minutes
    token = jwt.encode(
        {'username': username, 'exp': datetime.utcnow() + timedelta(minutes=30)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({'token':token}), 200

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token') # Get the token from headers

        if not token:
            return jsonify({'error': 'Token missing'}), 401 #unauthorized

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            username = data.get('username')
            user = User.query.filter_by(username=username).first()
            if user.role != 'admin':
                return jsonify({'error': 'Admin role required'}), 403
            
            g.admin_user = user
       
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)
    return decorated

#Create the inventory item (Part 2, bullet point #1)
@app.route('/api/inventory', methods=['POST'])
def create_inventory_item():
    #Check if user is logged in, will be used a lot
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    #Get the data from the request
    data = request.get_json()
    item_name = data.get('item_name')
    description = data.get('description')
    quantity = data.get('quantity')
    price = data.get('price')

    #Check if all the required fields are provided
    if not item_name or quantity is None or price is None:
        return jsonify({"error": "Missing required fields"}), 400

    #Create the new item
    new_item = InventoryItem(
        item_name=item_name,
        description=description,
        quantity=quantity,
        price=price,
        user_id=session['user_id']
    )
    #Add the item to the database   
    db.session.add(new_item)
    db.session.commit()

    return jsonify({"message": "Item created", "item_id": new_item.id}), 201

#protected route (requires valid JWT token)
@app.route('/api/admin/inventory', methods=['POST'])
@admin_token_required
def admin_create_inventory():
    data = request.get_json()
    item_name = data.get('item_name')
    description = data.get('description')
    quantity = data.get('quantity')
    price = data.get('price')

    admin_user = g.admin_user

    if not item_name or quantity is None or price is None:
        return jsonify({"error": "Missing required fields"}), 400

    new_item = InventoryItem(
        item_name=item_name,
        description=description,
        quantity=quantity,
        price=price,
        user_id=admin_user.id
    )
    db.session.add(new_item)
    db.session.commit()

    return jsonify({"message": "Admin item created", "item_id": new_item.id}), 201

#How to read Inventory Items (Part 2, bullet point #2)
@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    #Get all the items from the database that belong to the user
    items = InventoryItem.query.filter_by(user_id=session['user_id']).all()
    #Return the items in a JSON format
    result = [
        {
            "id": item.id,
            "item_name": item.item_name,
            "description": item.description,
            "quantity": item.quantity,
            "price": item.price
        }
        for item in items
    ]
    return jsonify(result), 200

@app.route('/api/admin/inventory', methods=['GET'])
@admin_token_required
def admin_get_inventory():
    items = InventoryItem.query.all()
    result = [{
        "id": item.id,
        "item_name": item.item_name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    } for item in items]

    return jsonify(result), 200

#Necessary for deletion logic
@app.route('/api/inventory/<int:item_id>', methods=['GET'])
def get_single_item(item_id):
    
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    #Get the item from the database 
    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404

    #Return the item in a JSON format
    result = {
        "id": item.id,
        "item_name": item.item_name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    }
    return jsonify(result), 200

@app.route('/api/admin/inventory/<int:item_id>', methods=['GET'])
@admin_token_required
def admin_get_single_item(item_id):
    item = InventoryItem.query.filter_by(id=item_id).first()

    if not item:
        return jsonify({"error": "Item not found"}), 404

    result = {
        "id": item.id,
        "item_name": item.item_name,
        "description": item.description,
        "quantity": item.quantity,
        "price": item.price
    }

    return jsonify(result), 200

# Check login status
@app.route('/api/auth/status', methods=['GET'])
def status():
    if 'user_id' in session:
        return jsonify({"status": "logged_in", "username": session['username']}), 200
    return jsonify({"status": "not_logged_in"}), 200

#Logout (4th bulllet point in #1) Clear yje session and remove the cookies

# User logout(define route)
@app.route('/api/auth/logout', methods=['GET'])
def logout():
    #This is where we clear the session it removes all data from the current user session
    session.clear()
    response = jsonify({"message": "Logged out successfully"})
    #Here is where we delete the session cookie
    response.delete_cookie('session')
    return response, 200

#update existing item by ID (Part 2, bullet point #3)
@app.route('/api/inventory/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    #Get the item from the database
    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404

    #Update the item
    data = request.get_json()
    item.item_name = data.get('item_name', item.item_name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)

    db.session.commit()
    return jsonify({"message": "Item updated"}), 200

@app.route('/api/admin/inventory/<int:item_id>', methods=['PUT'])
@admin_token_required
def admin_update_item(item_id):
    item = InventoryItem.query.filter_by(id=item_id).first()

    if not item:
        return jsonify({"error": "Item not found"}), 404

    data = request.get_json()
    item.item_name = data.get('item_name', item.item_name)
    item.description = data.get('description', item.description)
    item.quantity = data.get('quantity', item.quantity)
    item.price = data.get('price', item.price)

    db.session.commit()
    return jsonify({"message": "Item updated"}), 200


#delete existing item by ID (Part 2, bullet point #4)
@app.route('/api/inventory/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    item = InventoryItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Item deleted"}), 200


@app.route('/api/admin/inventory/<int:item_id>', methods=['DELETE'])
@admin_token_required
def admin_delete_item(item_id):
    item = InventoryItem.query.filter_by(id=item_id).first()

    if not item:
        return jsonify({"error": "Item not found"}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Item deleted"}), 200

#This is to start the flask app
if __name__ == '__main__':
    app.run(debug=True)
