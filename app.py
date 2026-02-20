from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Fake database (hashed password)
users = {
    "admin@example.com": generate_password_hash("Password123")
}

def valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # Input validation
        if not email or not password:
            flash("All fields are required.")
            return render_template("login.html")

        if not valid_email(email):
            flash("Invalid email format.")
            return render_template("login.html")

        # Authentication
        user_password = users.get(email)
        if not user_password or not check_password_hash(user_password, password):
            flash("Invalid email or password.")
            return render_template("login.html")

        session["user"] = email
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return f"Welcome, {session['user']}!"

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)