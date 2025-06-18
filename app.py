from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__, static_folder='../react-frontend/build', static_url_path='/')
CORS(app)  # faqat bitta app uchun qo‘llanilyapti

@app.route("/api/greet")
def greet():
    return jsonify({"message": "Hello from Flask!"})

@app.route("/")
def serve_react():
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    app.run(debug=True)
