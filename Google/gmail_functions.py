import json
import os
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from email.utils import parseaddr
from email.header import decode_header
import base64
import re
import asyncio
import aiohttp
import ssl
from datetime import datetime, timedelta, timezone
import jwt
from concurrent.futures import ThreadPoolExecutor
import hashlib
import logging

# Constants
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email', 'openid', 'https://www.googleapis.com/auth/userinfo.profile']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'
KEYWORDS = ['invoice', 'payment', 'receipt', 'bill', 'statement', 'purchase', 'order', 'transaction', 'confirmation', 'paid']

# Directories
TOKENS_FOLDER = 'tokens'
ATTACHMENTS_FOLDER = 'attachments'
LAST_CHECKED_FOLDER = 'last_checked'

credentials_lock = asyncio.Lock()
running_tasks = {}
executor = ThreadPoolExecutor()

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename='app_gmail.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_directories_exist():
    os.makedirs(TOKENS_FOLDER, exist_ok=True)
    os.makedirs(ATTACHMENTS_FOLDER, exist_ok=True)
    os.makedirs(LAST_CHECKED_FOLDER, exist_ok=True)


def get_last_checked_time(email):
    filepath = os.path.join(LAST_CHECKED_FOLDER, f"{email}.json")
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            data = json.load(file)
            return datetime.fromisoformat(data['last_checked'])
    return datetime.now(timezone.utc) - timedelta(minutes=1)


def save_last_checked_time(email, last_checked):
    filepath = os.path.join(LAST_CHECKED_FOLDER, f"{email}.json")
    with open(filepath, 'w') as file:
        json.dump({'last_checked': last_checked.isoformat()}, file)


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def get_header(msg, header_name):
    headers = msg.get('payload', {}).get('headers', [])
    for header in headers:
        if header['name'].lower() == header_name.lower():
            return header['value']
    return ""


async def check_keywords_in_email(msg):
    try:
        subject = get_header(msg, "Subject")
        if subject:
            decoded_subject, encoding = decode_header(subject)[0]
            if isinstance(decoded_subject, bytes):
                subject = decoded_subject.decode(encoding if encoding else "utf-8")
            for keyword in KEYWORDS:
                if re.search(re.escape(keyword), subject, re.IGNORECASE):
                    return keyword, []

        urls_to_download = []
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                content_type = part.get('mimeType')
                if part.get('filename'):
                    filename = part['filename']
                    for keyword in KEYWORDS:
                        if re.search(re.escape(keyword), filename, re.IGNORECASE):
                            return keyword, []
                if content_type in ["text/plain", "text/html"]:
                    try:
                        body = base64.urlsafe_b64decode(part['body'].get('data', '').encode('UTF-8')).decode('utf-8')
                        found_urls = re.findall(r'https://www\.greeninvoice\.co\.il/api/v1/documents/[^\s]+', body)
                        if found_urls:
                            urls_to_download.extend(found_urls)
                            return None, urls_to_download
                        for keyword in KEYWORDS:
                            if re.search(r'\b' + re.escape(keyword) + r'\b', body, re.IGNORECASE):
                                return keyword, urls_to_download
                    except Exception as e:
                        logging.error(f"Error decoding body: {e}")

        return None, urls_to_download
    except Exception as e:
        logging.error(f"Error in check_keywords_in_email: {e}")
        return None, []


async def save_attachments(message_id, parts, service):
    attachment_names = []
    for part in parts:
        if 'filename' in part and part['filename']:
            attachment_id = part['body'].get('attachmentId')
            if attachment_id:
                attachment = await asyncio.get_event_loop().run_in_executor(None, lambda: service.users().messages().attachments().get(userId='me', messageId=message_id, id=attachment_id).execute())
                file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                filepath = os.path.join(ATTACHMENTS_FOLDER, part['filename'])
                with open(filepath, 'wb') as file:
                    file.write(file_data)
                attachment_names.append(part['filename'])
    return attachment_names


async def download_and_save_url(url, email_id):
    # Create a hash of the URL to use as the file name
    hash_object = hashlib.sha256(url.encode())
    filename = os.path.join(ATTACHMENTS_FOLDER, f"{email_id}_{hash_object.hexdigest()}.pdf")

    async with aiohttp.ClientSession() as session:
        async with session.get(url, ssl=ssl.SSLContext()) as response:
            with open(filename, 'wb') as file:
                file.write(await response.read())
    return filename


def save_email_details(sender, recipient, attachment_names, email_id, urls=None):
    details = f"Sender: {sender}\nRecipient: {recipient}\nAttachments: {', '.join(attachment_names)}\n"
    if urls:
        details += f"Downloaded URLs: {', '.join(urls)}\n"
    details_path = os.path.join(ATTACHMENTS_FOLDER, f"{email_id}.txt")
    with open(details_path, 'w') as file:
        file.write(details)


def save_credentials(credentials_store, email):
    token_file_path = os.path.join(TOKENS_FOLDER, f'{email}.json')
    with open(token_file_path, 'w') as token_file:
        json.dump(credentials_store, token_file)


async def check_inbox(email):
    token_file_path = os.path.join(TOKENS_FOLDER, f'{email}.json')
    if not os.path.exists(token_file_path):
        raise FileNotFoundError(f"Token file {token_file_path} not found. The user must authenticate first.")

    with open(token_file_path, 'r') as token_file:
        token_data = json.load(token_file)

    credentials = Credentials(
        token=token_data['token'],
        refresh_token=token_data.get('refresh_token'),
        token_uri=token_data['token_uri'],
        client_id=token_data['client_id'],
        client_secret=token_data['client_secret'],
        scopes=token_data['scopes']
    )

    if credentials.refresh_token:
        await asyncio.get_event_loop().run_in_executor(None, credentials.refresh, Request())
        async with credentials_lock:
            credentials_store = credentials_to_dict(credentials)
            save_credentials(credentials_store, email)

    service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)

    last_checked = get_last_checked_time(email)
    now = datetime.now(timezone.utc)
    query = f"after:{int(last_checked.timestamp())}"

    max_retries = 5
    for attempt in range(max_retries):
        try:
            logging.debug(f"Checking inbox for {email}")
            results = await asyncio.get_event_loop().run_in_executor(None, lambda: service.users().messages().list(userId='me', q=query).execute())
            messages = results.get('messages', [])
            break
        except HttpError as e:
            if e.resp.status in [500, 503]:
                logging.warning(f"Retrying due to server error ({e.resp.status}). Attempt {attempt + 1}/{max_retries}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            else:
                logging.error(f"Error fetching messages: {e}")
                return [{"error": "Error fetching messages"}]

    new_emails = []
    if not messages:
        new_emails.append('No new emails.')
        logging.debug(f"No new emails for {email}")
    else:
        for message in messages:
            try:
                msg = await asyncio.get_event_loop().run_in_executor(None, lambda: service.users().messages().get(userId='me', id=message['id']).execute())
                keyword, urls_to_download = await check_keywords_in_email(msg)
                if urls_to_download:
                    logging.debug(f"Found URLs to download: {urls_to_download}")
                    sender = parseaddr(get_header(msg, "From"))[1]
                    recipient = parseaddr(get_header(msg, "To"))[1]
                    attachment_names = await save_attachments(message['id'], msg['payload'].get('parts', []), service)

                    downloaded_urls = [await download_and_save_url(url, message['id']) for url in urls_to_download]

                    save_email_details(sender, recipient, attachment_names, message['id'], downloaded_urls)
                    break  # Stop searching after finding and downloading URLs

                if keyword:
                    logging.debug(f"Keyword found: {keyword}")
                    sender = parseaddr(get_header(msg, "From"))[1]
                    recipient = parseaddr(get_header(msg, "To"))[1]
                    attachment_names = await save_attachments(message['id'], msg['payload'].get('parts', []), service)
                    save_email_details(sender, recipient, attachment_names, message['id'])
                new_emails.append(msg['snippet'])
            except Exception as e:
                logging.error(f"Error fetching message {message['id']}: {e}")
                new_emails.append(f"Error fetching message {message['id']}")

    save_last_checked_time(email, now)

    return new_emails


async def start_checking_inbox(email):
    while True:
        await check_inbox(email)
        await asyncio.sleep(60)


async def check_inbox_for_all_users():
    while True:
        current_emails = set()
        for filename in os.listdir(TOKENS_FOLDER):
            if filename.endswith('.json'):
                email = filename[:-5]  # Remove the .json extension
                current_emails.add(email)
                if email not in running_tasks:
                    running_tasks[email] = asyncio.create_task(start_checking_inbox(email))

        # Remove tasks for emails that no longer have a corresponding token file
        for email in list(running_tasks):
            if email not in current_emails:
                running_tasks[email].cancel()
                del running_tasks[email]

        await asyncio.sleep(60)  # Check all users every minute


def run_background_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()
