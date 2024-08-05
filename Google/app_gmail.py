import json
import os
import flask
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from flask import Flask, redirect, url_for, session, request, jsonify, send_file, make_response
from email.utils import parseaddr
from email.header import decode_header
import base64
import re
import asyncio
import aiohttp
import ssl
from datetime import datetime, timedelta, timezone
import threading
import jwt
from concurrent.futures import ThreadPoolExecutor

from gmail_functions import run_background_loop, check_inbox_for_all_users, get_last_checked_time, \
    check_keywords_in_email, get_header, save_attachments, save_email_details, save_last_checked_time, \
    start_checking_inbox, ensure_directories_exist, credentials_to_dict

# Constants
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email', 'openid',
          'https://www.googleapis.com/auth/userinfo.profile']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'
KEYWORDS = ["invoice", "payment", "receipt", "bill", "statement", "purchase", "order"]

# Directories
TOKENS_FOLDER = 'tokens'
ATTACHMENTS_FOLDER = 'attachments'
LAST_CHECKED_FOLDER = 'last_checked'

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your secret key

credentials_lock = asyncio.Lock()

running_tasks = {}

executor = ThreadPoolExecutor()


@app.route('/')
def index():
    return print_index_table()


@app.route('/list', methods=['GET'])
def list_tokens():
    try:
        token_files = [f for f in os.listdir(TOKENS_FOLDER) if f.endswith('.json')]
        return jsonify(token_files), 200
    except Exception as e:
        print(f"Error listing token files: {e}")
        return jsonify({"error": "Error listing token files"}), 500


@app.route('/delete', methods=['POST'])
def delete_files():
    try:
        data = request.json
        email = data.get('email')
        if not email:
            return jsonify({"error": "Email not provided"}), 400

        # Construct file paths
        token_file_path = os.path.join(TOKENS_FOLDER, f'{email}.json')
        last_checked_file_path = os.path.join(LAST_CHECKED_FOLDER, f'{email}.json')

        # Delete token file
        if os.path.exists(token_file_path):
            os.remove(token_file_path)

        # Delete last checked file
        if os.path.exists(last_checked_file_path):
            os.remove(last_checked_file_path)

        # Cancel and remove running tasks if any
        if email in running_tasks:
            running_tasks[email].cancel()
            del running_tasks[email]

        return jsonify({"message": f"Files for {email} deleted successfully"}), 200
    except Exception as e:
        print(f"Error deleting files for {email}: {e}")
        return jsonify({"error": "Error deleting files"}), 500


@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        log_file_path = 'app_gmail.log'
        if os.path.exists(log_file_path):
            return send_file(log_file_path, as_attachment=True)
        else:
            return jsonify({"error": "Log file not found"}), 404
    except Exception as e:
        print(f"Error retrieving log file: {e}")
        return jsonify({"error": "Error retrieving log file"}), 500


@app.route('/<path:url>')
def test_api_request(url):
    return jsonify({"message": "Email Added", "url": url}), 200


@app.route('/google/<path:url>')
def authorize(url):
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state
    session['url'] = url

    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    url = session.get('url')

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    # Decode the ID token to extract the email
    decoded_id_token = jwt.decode(credentials.id_token.encode('utf-8'), options={"verify_signature": False})
    email = decoded_id_token.get('email', credentials.client_id)

    ensure_directories_exist()
    token_file_path = os.path.join(TOKENS_FOLDER, f'{email}.json')

    with open(token_file_path, 'w') as token_file:
        json.dump(credentials_to_dict(credentials), token_file)

    # Submit the coroutine to the background event loop
    asyncio.run_coroutine_threadsafe(start_checking_inbox(email), bg_loop)

    return redirect(url_for('test_api_request', url=url))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return ('Credentials successfully revoked.' + print_index_table())
    else:
        return ('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/test">Test an API request</a></td>' +
            '<td>Submit an API request and see a formatted JSON response. ' +
            '    Go through the authorization flow if there are no stored ' +
            '    credentials for the user.</td></tr>' +
            '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Revoke the access token associated with the current user ' +
            '    session. After revoking credentials, if you go to the test ' +
            '    page, you should see an <code>invalid_grant</code> error.' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token currently stored in the user session. ' +
            '    After clearing the token, if you <a href="/test">test the ' +
            '    API request</a> again, you should go back to the auth flow.' +
            '</td></tr></table>')


def run_background_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


if __name__ == '__main__':
    ensure_directories_exist()
    bg_loop = asyncio.new_event_loop()
    t = threading.Thread(target=run_background_loop, args=(bg_loop,), daemon=True)
    t.start()

    # Start checking inbox for all users
    asyncio.run_coroutine_threadsafe(check_inbox_for_all_users(), bg_loop)

    app.run(ssl_context='adhoc', port=4000)
