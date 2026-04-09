from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import secrets
import threading
from scanner.engine import ScannerEngine
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DUMMY_TOKEN = "hackbuddy_secure_token_123"

# Store active scans by URL (in-memory for demo)
active_scans = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/result')
def dashboard():
    target_url = request.args.get('url', 'https://example-app.com')
    # Start scan automatically if it hasn't been started for this url
    if target_url and target_url not in active_scans:
        engine = ScannerEngine(target_url)
        active_scans[target_url] = engine
        threading.Thread(target=engine.run_scan).start()
    return render_template('dashboard.html', target_url=target_url)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400
        
    username = data.get('username')
    password = data.get('password')
    
    if username and password:
        return jsonify({
            "message": "Login successful",
            "token": DUMMY_TOKEN
        }), 200
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/scan', methods=['POST'])
def start_scan():
    auth_header = request.headers.get('Authorization')
        
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    if url in active_scans and active_scans[url].result.status == "running":
         return jsonify({"message": "A scan is already in progress for this URL", "current_scan": url}), 409
         
    engine = ScannerEngine(url)
    active_scans[url] = engine
    
    # Run scan in background
    threading.Thread(target=engine.run_scan).start()
    
    return jsonify({
        "message": "Scan started successfully",
        "url": url,
        "status": "running"
    }), 202

@app.route('/api/results', methods=['GET'])
def get_results():
    # If the frontend requests results, return the latest one
    if not active_scans:
        return jsonify({"status": "idle", "progress": 0, "findings": []}), 200
        
    # Just grab the first scan for demo purposes, or require URL
    url = request.args.get('url')
    if not url:
        url = list(active_scans.keys())[-1]
        
    engine = active_scans.get(url)
    if engine:
        return jsonify(engine.get_status()), 200
        
    return jsonify({"error": "Scan not found"}), 404

@app.route('/api/report/pdf', methods=['GET'])
def get_pdf_report():
    if os.path.exists("scan_report.pdf"):
        return send_file("scan_report.pdf", as_attachment=True)
    return jsonify({"error": "Report not found. Has a scan completed?"}), 404

@app.route('/api/contact', methods=['POST'])
def contact():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    message = request.form.get('message')
    
    print(f"Contact form submitted by: {first_name} {last_name} ({email}) - {message}")
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
