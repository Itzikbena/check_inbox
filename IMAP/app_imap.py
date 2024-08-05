from flask import Flask, request, jsonify, Response
from functions import ensure_directories_exist, start_all_saved_credentials, start_checking, delete_credentials, load_credentials
import os
import logging

app = Flask(__name__)

# Ensure directories and logging configuration are set up
ensure_directories_exist()

@app.route('/imap', methods=['POST'])
def start_checking_route():
    data = request.json
    server = data.get('server')
    port = data.get('port', 993)  # Default to 993 if not provided
    username = data.get('username')
    password = data.get('password')

    if not server or not username or not password:
        return jsonify({"error": "Missing required fields"}), 400

    message, status = start_checking(server, port, username, password)
    return jsonify({"message": message}), status

@app.route('/list', methods=['GET'])
def list_credentials_route():
    credentials_list = load_credentials()
    usernames = [cred['username'] for cred in credentials_list]
    return jsonify(usernames)

@app.route('/delete', methods=['POST'])
def delete_credentials_route():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    message, status = delete_credentials(email)
    return jsonify({"message": message}), status

@app.route('/log', methods=['GET'])
def get_log():
    log_file_path = 'app.log'
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'r') as file:
                log_content = file.read()
            return Response(log_content, mimetype='text/plain', headers={"Content-Disposition": "attachment;filename=app.log"})
        except Exception as e:
            logging.error(f"Error reading log file: {e}")
            return jsonify({"error": "Failed to read log file"}), 500
    else:
        logging.error("Log file not found")
        return jsonify({"error": "Log file not found"}), 404

if __name__ == '__main__':
    start_all_saved_credentials()
    app.run(debug=False, port=6000)  # Change the port to 6000
