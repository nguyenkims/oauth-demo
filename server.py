"""Authorization server
This server handles:
- user login, logout
- authorization form for user to accept sharing their data with a client

User is consider logged in if there's "user_id" in session.
"""
import os
import random
import string
from functools import wraps

import bcrypt
from flask import (
    Flask,
    request,
    redirect,
    jsonify,
    session,
    render_template,
    url_for,
    g,
)
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Cookie is bound to localhost domain,
# so as a workaround for this demo,
# server and client use the same secret key so they can share session
app.secret_key = "secret"
app.template_folder = "templates/server"

db = SQLAlchemy(app)


# <<< Models >>>
class ModelMixin(object):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)


class Client(db.Model, ModelMixin):
    client_id = db.Column(db.String(128), unique=True)
    client_secret = db.Column(db.String(128))
    redirect_uri = db.Column(db.String(1024))
    name = db.Column(db.String(128))


class User(db.Model, ModelMixin):
    email = db.Column(db.String(128), unique=True)
    salt = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(128))

    def set_password(self, password):
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode(), salt).decode()
        self.salt = salt.decode()
        self.password = password_hash

    def check_password(self, password) -> bool:
        password_hash = bcrypt.hashpw(password.encode(), self.salt.encode())
        return self.password.encode() == password_hash


class AuthorizationCode(db.Model, ModelMixin):
    code = db.Column(db.String(128), unique=True)
    client_id = db.Column(db.ForeignKey(Client.id))
    user_id = db.Column(db.ForeignKey(User.id))


class OAuthToken(db.Model, ModelMixin):
    access_token = db.Column(db.String(128), unique=True)
    client_id = db.Column(db.ForeignKey(Client.id))
    user_id = db.Column(db.ForeignKey(User.id))

    user = db.relationship(User)


# <<< Init database and add some data >>>


def init_data():
    # fake data
    client = Client(
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="http://localhost:7000/callback",
        name="Continental",
    )
    db.session.add(client)

    user = User(id=1, email="john@wick.com", name="John Wick")
    user.set_password("password")
    db.session.add(user)

    db.session.commit()


# Remove db if exist
if os.path.exists("db.sqlite"):
    os.remove("db.sqlite")

db.create_all()
init_data()


def random_string(length=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(length))


def require_login(f):
    """
    Decorator that extracts the user_id from session and set g.user to this user.
    If no user_id in session or user does not exist, return 400
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return "you need to login", 400

        user_id = session["user_id"]
        user = User.query.get(user_id)
        if not user:
            return "No such user. Please login again.", 400

        g.user = user
        return f(*args, **kwargs)

    return decorated


@app.route("/", methods=["GET", "POST"])
def index():
    """This home page handles user login"""
    user = error = None

    # user post login
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if not user:
            error = f"No such user with email {email}"
            return render_template("home.html", user=user, error=error)

        if not user.check_password(password):
            error = "Wrong password"
            return render_template("home.html", user=None, error=error)

        # Mark user as login
        session["user_id"] = user.id

        # The login can come from the authorization page. In this case redirect user back to this page.
        if "redirect_after_login" in session:
            url = session["redirect_after_login"]
        else:
            url = url_for(".index")
        return redirect(url)
    else:
        if "user_id" in session:
            user_id = session["user_id"]
            user = User.query.get(user_id)

        return render_template("home.html", user=user, error=error)


@app.route("/logout")
@require_login
def logout():
    session.pop("user_id", None)
    return redirect(url_for(".index"))


# <<< Authorization server endpoints >>>


@app.route("/oauth/authorize")
def oauth_authorize():
    """Redirected from client when user clicks on "Login with Server".
    This is a GET request with the following field in url
    - client_id
    - (optional) state
    - response_type: must be code
    """
    client_id = request.args.get("client_id")
    state = request.args.get("state")
    response_type = request.args.get("response_type")

    # sanity check
    if not response_type == "code":
        return "response_type must be code", 400

    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        return f"no such client with id {client_id}", 400

    user = None
    if "user_id" in session:
        user_id = session["user_id"]
        user = User.query.get(user_id)

    # If user is not logged in, they will be ask to login.
    if not user:
        # after user logs in, redirect user back to this page
        session["redirect_after_login"] = request.url

    return render_template("authorize.html", user=user, client=client, state=state)


@app.route("/oauth/allow", methods=["POST"])
@require_login
def allow_client():
    """
    This page handles the POST request when user clicks on "Allow" on the authorization page.
    At this point, user must be logged in.
    Once user approves, this will redirect user back to client with the authorization code and state.
    :return:
    """
    user = g.user
    client_id = request.form.get("client-id")
    state = request.form.get("state")
    client = Client.query.get(client_id)

    # Create authorization code
    auth_code = AuthorizationCode(
        client_id=client.id, user_id=user.id, code=random_string()
    )
    db.session.add(auth_code)
    db.session.commit()

    redirect_url = f"{client.redirect_uri}?code={auth_code.code}&state={state}"
    return redirect(redirect_url)


@app.route("/oauth/token", methods=["POST"])
def get_access_token():
    """
    Calls by client to exchange the access token given the authorization code.
    The client authentications using Basic Authentication.
    The form contains the following data:
    - grant_type: must be "authorization_code"
    - code: the code obtained in previous step
    """
    # Basic authentication
    client_id = request.authorization.username
    client_secret = request.authorization.password

    client = Client.query.filter_by(
        client_id=client_id, client_secret=client_secret
    ).first()

    if not client:
        return "wrong client-id or client-secret", 400

    # Get code from form data
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")

    # sanity check
    if grant_type != "authorization_code":
        return "grant_type must be authorization_code"

    auth_code: AuthorizationCode = AuthorizationCode.query.filter_by(code=code).first()
    if not auth_code:
        return f"no such authorization code {code}", 400

    if auth_code.client_id != client.id:
        return f"are you sure this code belongs to you?", 400

    # Create token
    oauth_token = OAuthToken(
        client_id=auth_code.client_id,
        user_id=auth_code.user_id,
        access_token=random_string(40),
    )
    db.session.add(oauth_token)

    # Auth code can be used only once
    db.session.delete(auth_code)

    db.session.commit()

    return jsonify(
        {
            "access_token": oauth_token.access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "create delete",
        }
    )


@app.route("/profile")
def profile():
    """Call by client to get user information
    Usually bearer token is used.
    """
    access_token = request.headers["AUTHORIZATION"].replace("Bearer ", "")
    oauth_token = OAuthToken.query.filter_by(access_token=access_token).first()
    if not oauth_token:
        return "Need bearer token", 400

    user = oauth_token.user

    return jsonify({"email": user.email, "name": user.name})


if __name__ == "__main__":
    app.run(debug=True)
