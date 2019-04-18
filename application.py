from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Remember Session
session["user_id"]

@app.route("/", methods = ["GET"])
@login_required
def index():
    return render_template("index.html")

@app.route("/piechart", methods = ["GET"])
@login_required
def piechart():
    return render_template("piechart.html")

@app.route("/doughnut", methods = ["GET"])
@login_required
def doughnut():
    return render_template("doughnut.html")

@app.route("/polararea", methods = ["GET"])
@login_required
def polararea():
    return render_template("polararea.html")

@app.route("/verticalbargraph", methods = ["GET"])
@login_required
def verticalbargraph():
    return render_template("verticalbargraph.html")

@app.route("/horizontalbargraph", methods = ["GET"])
@login_required
def horizontalbargraph():
    return render_template("horizontalbargraph.html")

@app.route("/linegraphcategory", methods = ["GET"])
@login_required
def linegraphcategory():
    return render_template("linegraphcategory.html")

@app.route("/linegraphplotting", methods = ["GET"])
@login_required
def linegraphplotting():
    return render_template("linegraphplotting.html")

@app.route("/scatterplot", methods = ["GET"])
@login_required
def scatterplot():
    return render_template("scatterplot.html")

@app.route("/bubblechart", methods = ["GET"])
@login_required
def bubblechart():
    return render_template("bubblechart.html")

@app.route("/radarchart", methods = ["GET"])
@login_required
def radarchart():
    return render_template("radarchart.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # connecting to the database
        connection = sqlite3.connect("users.db")

        # cursor
        db = connection.cursor()

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        db.execute("SELECT * FROM users WHERE username = :username",{'username': request.form.get("username")})
        rows = db.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # close the connection
        connection.close()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # connecting to the database
        connection = sqlite3.connect("users.db")

        # cursor
        db = connection.cursor()

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure username does not exist in database already
        db.execute("SELECT username FROM users")
        usernames = db.fetchall()
        print(usernames)

        for i in usernames:
            if i[0] == request.form.get("username"):
                return apology("Username is taken", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # Ensure password matches confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password must match confirmation", 400)

        # Hash the user’s password with generate_password_hash.
        hashed = generate_password_hash(request.form.get("password"))

        # INSERT the new user into users, storing a hash of the user’s password, not the password itself.
        db.execute("INSERT INTO users (username, hash) VALUES (:username,:hashed)",
                   {'username': request.form.get("username"), 'hashed': hashed})


        # To save the changes in the files. Never skip this.
        # If we skip this, nothing will be saved in the database.
        connection.commit()

        # close the connection
        connection.close()

        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Changes password"""
    if request.method == "POST":

        # connecting to the database
        connection = sqlite3.connect("users.db")

        # cursor
        db = connection.cursor()

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide confirmation", 403)

        # Ensure password matches confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password must match confirmation", 403)

        # Hash the user’s password with generate_password_hash.
        hashed = generate_password_hash(request.form.get("password"))

        # UPDATE the password
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", {'id': session["user_id"], 'hash': hashed})

        # To save the changes in the files. Never skip this.
        # If we skip this, nothing will be saved in the database.
        connection.commit()

        # close the connection
        connection.close()

        return redirect("/")
    else:
        return render_template("change.html")

@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    # connecting to the database
    connection = sqlite3.connect("users.db")

    # cursor
    db = connection.cursor()

    username = request.args.get("username")
    db.execute("SELECT username FROM users")
    usernames = db.fetchall()

    # close the connection
    connection.close()

    if len(username) > 0:
        for i in usernames:
            if i[0] == username:
                return jsonify(False)
        return jsonify(True)
    else:
        return jsonify(False)


