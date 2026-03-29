from flask_cors import CORS

ALLOWED_ORIGINS = [
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/signup.html",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/success.html",
    "https://solid-bassoon-r4wwp45rpr6v3qj7-5000.app.github.dev/totp.html",
]

CORS(
    app,
    origins=ALLOWED_ORIGINS,
    methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True,
)
