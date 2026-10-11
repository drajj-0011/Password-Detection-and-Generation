from flask import Flask, jsonify, request, send_from_directory

from password_lab import (
    CHAR_SETS,
    MAX_LENGTH,
    MIN_LENGTH,
    analyze_password,
    generate_password,
)

app = Flask(__name__, static_folder="static", static_url_path="/static")


@app.after_request
def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str) or len(password) > 256:
        return jsonify(error="Invalid password input."), 400
    return jsonify(analyze_password(password))


@app.post("/api/generate")
def api_generate():
    data = request.get_json(silent=True) or {}
    try:
        length = int(data.get("length", 20))
        use = [k for k in data.get("sets", list(CHAR_SETS)) if k in CHAR_SETS]
        password = generate_password(length, use)
    except (TypeError, ValueError) as err:
        return jsonify(error=str(err)), 400
    return jsonify(password=password, length=len(password), types=len(use))


@app.get("/api/config")
def api_config():
    return jsonify(min_length=MIN_LENGTH, max_length=MAX_LENGTH, sets=list(CHAR_SETS))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
