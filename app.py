from flask import Flask, request
from datetime import datetime, timedelta

app = Flask(__name__)

# Attack patterns
attack_patterns = [
    "or 1=1",
    "<script>",
    "../",
    "--"
]

# Store request count per IP
ip_requests = {}
REQUEST_LIMIT = 5        # max requests
TIME_WINDOW = 10         # seconds


def log_event(message):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs.txt", "a") as file:
        file.write(f"[{time}] {message}\n")


def is_rate_limited(ip):
    now = datetime.now()

    if ip not in ip_requests:
        ip_requests[ip] = []

    # Remove old requests
    ip_requests[ip] = [
        t for t in ip_requests[ip]
        if now - t < timedelta(seconds=TIME_WINDOW)
    ]

    ip_requests[ip].append(now)

    if len(ip_requests[ip]) > REQUEST_LIMIT:
        log_event(f"IP: {ip} | Brute-force detected | Rate Limited")
        return True

    return False


def is_attack(user_input, ip):
    if user_input:
        user_input = user_input.lower()
        for pattern in attack_patterns:
            if pattern in user_input:
                log_event(f"IP: {ip} | Attack Input: {user_input}")
                return True
    return False


@app.route("/")
def home():
    return "Welcome to SentinelShield"


@app.route("/search")
def search():
    ip = request.remote_addr
    query = request.args.get("q")

    if is_rate_limited(ip):
        return "⛔ Too many requests. Try again later.", 429

    if is_attack(query, ip):
        return "⚠️ Malicious request detected!", 403

    return f"You searched for: {query}"


@app.route("/login")
def login():
    ip = request.remote_addr
    username = request.args.get("username")

    if is_rate_limited(ip):
        return "⛔ Too many login attempts. Access blocked.", 429

    if is_attack(username, ip):
        return "⚠️ Attack detected! Login blocked.", 403

    return f"Login attempt for user: {username}"


if __name__ == "__main__":
    app.run(debug=True)
