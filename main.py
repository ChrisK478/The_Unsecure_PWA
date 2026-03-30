from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask_cors import CORS
from urllib.parse import urlparse
from flask import abort, url_for
from flask_wtf.csrf import CSRFProtect

import user_management as dbHandler
import pyotp
import qrcode
import io
import base64


ALLOWED_ORIGINS = [
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/signup.html",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/success.html",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/totp.html",
]
app = Flask(__name__)
app.secret_key = "change"
csrf = CSRFProtect(app)
CORS(
    app,
    origins=ALLOWED_ORIGINS,
    methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True,
)


def safe_redirect(target):
    if not target:
        return url_for("home")
    parsed = urlparse(target)
    # block absolute URLs or protocol-relative URLs
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        abort(400)
    # optionally allow only specific paths
    allowed = {
        "/index.html",
        "/signup.html",
        "/success.html",
        "/totp.html",
        "/setup-2fa",
    }
    if target not in allowed:
        abort(400)
    return target


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        feedback_list = dbHandler.listFeedback()
        return render_template(
            "/success.html", state=True, value="Back", feedback_list=feedback_list
        )
    else:
        feedback_list = dbHandler.listFeedback()
        return render_template(
            "/success.html", state=True, value="Back", feedback_list=feedback_list
        )


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    username = session.get("user")
    if not username:
        return redirect("/index.html")

    # If already enabled, skip setup
    if dbHandler.is_totp_enabled(username):
        feedback_list = dbHandler.listFeedback()
        return render_template(
            "/success.html", value=username, state=True, feedback_list=feedback_list
        )

    secret = dbHandler.get_totp_secret(username)
    if not secret:
        secret = pyotp.random_base32()
        dbHandler.set_totp_secret(username, secret)

    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name="The_Unsecure_PWA")

    # generate QR as base64 image
    img = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_data = base64.b64encode(buffer.getvalue()).decode("utf-8")

    if request.method == "POST":
        code = request.form["code"]
        if totp.verify(code):
            dbHandler.enable_totp(username)
            dbHandler.listFeedback()
            return redirect(
                "/success.html"
            )  # <-- this line replaces the old render_template success
        return render_template(
            "setup_2fa.html", qr=qr_data, secret=secret, error="Invalid code"
        )

    return render_template("setup_2fa.html", qr=qr_data, secret=secret)


@app.route("/totp.html", methods=["GET", "POST"])
def totp_verify():
    pending = session.get("pending_2fa")
    if not pending:
        return redirect("/index.html")

    secret = dbHandler.get_totp_secret(pending)
    if not secret:
        # If no secret found, force setup
        session.pop("pending_2fa", None)
        session["user"] = pending
        return redirect("/setup-2fa")

    totp = pyotp.TOTP(secret)

    if request.method == "POST":
        code = request.form["code"]
        if totp.verify(code):
            session.pop("pending_2fa", None)
            session["user"] = pending
            feedback_list = dbHandler.listFeedback()
            return render_template(
                "/success.html", value=pending, state=True, feedback_list=feedback_list
            )
        return render_template("totp.html", error="Invalid code")

    return render_template("totp.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            if dbHandler.is_totp_enabled(username):
                session["pending_2fa"] = username
                return redirect("/totp.html")
            else:
                # Redirect immediately to setup after login
                session["user"] = username
                return redirect("/setup-2fa")
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"

    # If CSP already exists, append frame-ancestors; otherwise set a full CSP.
    csp = response.headers.get("Content-Security-Policy")
    if csp:
        if "frame-ancestors" not in csp:
            csp = f"{csp}; frame-ancestors 'none'"
            response.headers["Content-Security-Policy"] = csp
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
    return response


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="127.0.0.1", port=5000)
