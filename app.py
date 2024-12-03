from flask import (Flask,
                   url_for,
                   session,
                   redirect,
                   render_template)
from authlib.integrations.flask_client import OAuth
import os

app = Flask(__name__)
app.secret_key = os.environ['secret_key']
app.config["DISIDAUTH_CLIENT_ID"] = os.environ['client_id']
app.config["DISIDAUTH_CLIENT_SECRET"] = os.environ['client_secret']

oauth = OAuth(app)
oauth.register(
    name="disidauth",
    server_metadata_url="https://unifyidapi-dev.auth.pc-daiwabo.co.jp/oauth/v2/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid disAppliUserId"
        ,"code_challenge_method": "S256"
    }
)

@app.route("/")
def homepage():
    user = session.get("user")
    return render_template('index.html', user=user)

@app.route("/login", methods=["GET"])
def login():
    redirect_uri = url_for("auth", _external=True)
    return oauth.disidauth.authorize_redirect(redirect_uri)

@app.route("/ret")
def auth():
    token = oauth.disidauth.authorize_access_token()
    user = oauth.disidauth.userinfo(token=token)
    session["user"] = user
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    port = os.environ.get('FLASK_PORT') or 8080
    port = int(port)
#    app.run(host='0.0.0.0', port=44355, ssl_context=('openssl/server.crt', 'openssl/server.key'), threaded=True, debug=True)
    app.run(host='0.0.0.0', port=port, debug=True)
