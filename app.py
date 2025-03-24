import os
import pandas as pd
import joblib
from flask import Flask, url_for, redirect, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from forms import InputForm  # Ensure `forms.py` exists with `InputForm`

# Initialize Flask app
app = Flask(__name__)

# Security key (move to environment variable for production)
app.config["SECRET_KEY"] = "super_secret_key"

# Database configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize Database and Other Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Load Model
try:
    model = joblib.load("model.joblib")
except FileNotFoundError:
    model = None  # Handle missing model gracefully

# Define User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for bcrypt hash

# Load User Callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))

        flash("Invalid username or password", "danger")

    return render_template("login.html")

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()  # Properly log out user
    return redirect(url_for("login"))

# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        new_username = request.form.get("username")
        email = request.form["email"]
        new_password = request.form.get("password")

        # Validate input
        if not new_username or not new_password:
            flash("Username and password cannot be empty.", "danger")
            return redirect(url_for("register"))

        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for("register"))

        # Check if user already exists
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash("Username already exists! Choose a different one.", "danger")
            return redirect(url_for("register"))

        # Store user with hashed password
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        new_user = User(username=new_username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Index Route (Protected)
@app.route("/index")
@login_required
def index():
    return render_template("index.html", username=current_user.username)

# Prediction Page (Protected)
@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():
    form = InputForm()

    if request.method == "POST" and form.validate_on_submit():
        no_of_passengers = form.no_of_passengers.data

        x_new = pd.DataFrame({
            "airline": [form.airline.data],
            "date_of_journey": [form.date_of_journey.data.strftime("%Y-%m-%d")],
            "source": [form.source.data],
            "destination": [form.destination.data],
            "dep_time": [form.dep_time.data.strftime("%H:%M:%S")],
           
            "total_stops": [form.total_stops.data],
            "no_of_passengers": [form.no_of_passengers.data],
            "additional_info": [form.additional_info.data],
        })

        if model:
            predicted_price_per_person = model.predict(x_new)[0]  # Prediction for one passenger
            total_price = predicted_price_per_person * no_of_passengers  # Multiply by passenger count
            message = f"The predicted price per passenger is {predicted_price_per_person:,.0f} INR"
            message += f"For {no_of_passengers} passenger(s), the total price is {total_price:,.0f} INR."
        else:
            message = "Model not found. Please upload a valid model."

        return render_template("predict.html", title="Predict", form=form, output=message)

    return render_template("predict.html", title="Predict", form=form)

# About Route
@app.route("/about")
def about():
    return render_template("about.html")  # Ensure you have an about.html file in templates/

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure database tables exist
    app.run(debug=True)
