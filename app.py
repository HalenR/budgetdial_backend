from flask import Flask, jsonify, request, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from plaid.api import plaid_api
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_get_request import TransactionsGetRequest
from plaid import Configuration, ApiClient
from datetime import datetime, timedelta
import os


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if unauthorized

# User model for Flask-Login and SQLAlchemy
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    access_token = db.Column(db.String, nullable=True)
    device_id = db.Column(db.String(16), unique=True, nullable=True)  
    budget = db.Column(db.Float, nullable=True, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Required by Flask-Login
    def get_id(self):
        return self.user_id

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(user_id=user_id).first()

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Unauthorized"}), 401

# Plaid setup (your keys)
PLAID_CLIENT_ID = os.environ.get("PLAID_CLIENT_ID")
PLAID_SECRET = os.environ.get("PLAID_SECRET")
configuration = Configuration(
    host="https://sandbox.plaid.com",
    api_key={
        "clientId": PLAID_CLIENT_ID,
        "secret": PLAID_SECRET,
    }
)
api_client = ApiClient(configuration)
client = plaid_api.PlaidApi(api_client)

@app.route("/api/get_access_token", methods=["GET"])
def get_access_token_by_device():
    device_id = request.args.get("device_id")
    if not device_id:
        return jsonify({"error": "Missing device_id"}), 400
    user = User.query.filter_by(device_id=device_id).first()
    if not user:
        app.logger.info(f"No user found with device_id: {device_id}")
        return jsonify({"error": "No token"}), 404

    if not user.access_token:
        app.logger.info(f"User with device_id {device_id} has no access token")
        return jsonify({"error": "No token"}), 404

    app.logger.info(f"Returning token for device_id {device_id}: {user.access_token}")
    return jsonify({"access_token": user.access_token})

@app.route("/api/register_device", methods=["POST"])
def register_device():
    data = request.get_json()
    user_id = data.get("user_id")
    device_id = data.get("device_id")

    if not user_id or not device_id:
        return jsonify({"error": "Missing user_id or device_id"}), 400

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.device_id = device_id
    db.session.commit()
    return jsonify({"message": "Device registered", "device_id": device_id})

@app.route("/")
def index():
    return jsonify({"messgae": "Welcome to the backend API"})

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    user_id = data.get("user_id")
    password = data.get("password")
    device_id = data.get("device_id")

    if not user_id or not password or not device_id:
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter_by(user_id=user_id).first():
        return jsonify({"error": "User already exists"}), 400

    if User.query.filter_by(device_id=device_id).first():
        return jsonify({"error": "Device ID already registered"}), 400

    new_user = User(user_id=user_id, device_id=device_id)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True)  # force JSON parse, silent to avoid error
    if not data:
        return jsonify({"error": "Expected JSON data"}), 400

    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(user_id=user_id).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})

@app.route("/api/create_link_token", methods=["GET", "POST"])
def create_link_token():
    try:
        user_id = request.json.get("user_id", "user-123") if request.method == "POST" else "user-123"
        request_data = LinkTokenCreateRequest(
            user=LinkTokenCreateRequestUser(client_user_id=user_id),
            client_name="Spending Tracker",
            products=[Products("transactions")],
            country_codes=[CountryCode("US")],
            language="en"
        )
        response = client.link_token_create(request_data)
        return jsonify(response.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exchange_public_token", methods=["POST"])
def exchange_public_token():
    data = request.json
    public_token = data.get("public_token")
    user_id = data.get("user_id")
    password = data.get("password")

    if not public_token or not user_id or not password:
        return jsonify({"error": "Missing fields"}), 400

    user = User.query.filter_by(user_id=user_id).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        response = client.item_public_token_exchange(
            ItemPublicTokenExchangeRequest(public_token=public_token)
        )
    except Exception as e:
        return jsonify({"error": "Failed to exchange public token", "details": str(e)}), 500

    access_token = response["access_token"]
    user.access_token = access_token
    db.session.commit()

    return jsonify({"access_token": access_token})

@app.route("/api/get_access_token_by_user", methods=["GET"])
def get_access_token():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.access_token:
        return jsonify({"error": "No access token set"}), 404

    return jsonify({"access_token": user.access_token})

from flask import current_app

@app.route("/api/budget_check_token", methods=["POST"])
def budget_check_token():
    data = request.get_json()
    access_token = data.get("access_token")
    app.logger.info(f"Received access_token: {access_token!r}")

    if not access_token:
        return jsonify({"error": "Missing access token"}), 400

    access_token = access_token.strip().strip('\'"')
    current_app.logger.info(f"Received access_token: {access_token}")

    # Exact match search for user
    user = User.query.filter_by(access_token=access_token).first()

    if not user:
        app.logger.warning(f"Invalid access token attempted: {access_token!r}")
        return jsonify({"error": "Invalid access token"}), 403

    # Plaid API call wrapped in try/except
    try:
        start_date = (datetime.now() - timedelta(days=30)).date()
        end_date = datetime.now().date()

        req = TransactionsGetRequest(
            access_token=user.access_token,
            start_date=start_date,
            end_date=end_date,
        )
        res = client.transactions_get(req)
        transactions = res.to_dict().get("transactions", [])

        total_spent = sum(txn.get("amount", 0) for txn in transactions)
        budget = user.budget if user.budget is not None else 100000  # fallback default

        return jsonify({
            "total_spent": total_spent,
            "budget": budget,
            "within_budget": total_spent <= budget
        })

    except Exception as e:
        current_app.logger.error(f"Plaid API error: {e}")
        return jsonify({"error": "Plaid API error or invalid access token"}), 403


@app.route("/api/budget_check", methods=["POST"])
@login_required
def budget_check():
    user = User.query.filter_by(user_id=current_user.user_id).first()
    if not user or not user.access_token:
        return jsonify({"error": "No bank linked"}), 400

    start_date = (datetime.now() - timedelta(days=30)).date()
    end_date = datetime.now().date()

    req = TransactionsGetRequest(
        access_token=user.access_token,
        start_date=start_date,
        end_date=end_date,
    )
    res = client.transactions_get(req)
    transactions = res.to_dict()["transactions"]
    total_spent = sum(txn["amount"] for txn in transactions)
    
    budget = user.budget if user.budget is not None else 100000.0

    return jsonify({
        "total_spent": total_spent,
        "budget": budget,
        "within_budget": total_spent <= budget
    })

@app.route("/api/set_budget", methods=["POST"])
@login_required
def set_budget():
    data = request.json
    new_budget = data.get("budget")
    if new_budget is None:
        return jsonify({"error": "Missing budget"}), 400

    try:
        new_budget = float(new_budget)
    except ValueError:
        return jsonify({"error": "Invalid budget value"}), 400

    user = User.query.filter_by(user_id=current_user.user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.budget = new_budget
    db.session.commit()

    return jsonify({"message": "Budget updated", "budget": new_budget})

@app.route("/api/set_budget_token", methods=["POST"])
def set_budget_token():
    data = request.get_json()
    access_token = data.get("access_token")
    new_budget = data.get("budget")

    if not access_token:
        return jsonify({"error": "Missing access token"}), 400
    if new_budget is None:
        return jsonify({"error": "Missing budget"}), 400

    try:
        new_budget = float(new_budget)
    except ValueError:
        return jsonify({"error": "Invalid budget value"}), 400

    user = User.query.filter_by(access_token=access_token).first()
    if not user:
        return jsonify({"error": "Invalid access token"}), 403

    user.budget = new_budget
    db.session.commit()

    return jsonify({"message": "Budget updated", "budget": new_budget})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
