import os

from flask import Flask, request, redirect, session, url_for, render_template
from requests_oauthlib import OAuth2Session

app = Flask(__name__)
app.secret_key = "secret"
app.template_folder = "templates/client"

# this client is created in server.py
client_id = "client-id"
client_secret = "client-secret"

# Authorization code and token url
authorization_base_url = "http://localhost:5000/oauth/authorize"
token_url = "http://localhost:5000/oauth/token"

# Resource url
resource_server_url = "http://localhost:5000/profile"


@app.route("/")
def index():
    user = None
    if "user" in session:
        user = session["user"]

    return render_template("home.html", user=user)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for(".index"))


@app.route("/login")
def login():
    """
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    server = OAuth2Session(client_id)
    authorization_url, state = server.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    return redirect(authorization_url)


@app.route("/callback", methods=["GET"])
def callback():
    """
    Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    server = OAuth2Session(client_id, state=session["oauth_state"])
    token = server.fetch_token(
        token_url, client_secret=client_secret, authorization_response=request.url
    )

    server = OAuth2Session(client_id, token=token)
    user_info = server.get(resource_server_url).json()

    session["user"] = user_info["name"]

    return redirect(url_for(".index"))


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    app.run(debug=True, port=7000, threaded=False)
