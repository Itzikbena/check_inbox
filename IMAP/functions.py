import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from threading import Thread, Event
import time
import os
import json
from datetime import datetime, timezone, timedelta
import re
import requests
import hashlib
import logging

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Directories for storing credentials, attachments, and last checked times
TOKENS_FOLDER = 'tokens'
ATTACHMENTS_FOLDER = 'attachments'
LAST_CHECKED_FOLDER = 'last_checked'

# Keywords to search for in emails
KEYWORDS = ['invoice', 'payment', 'receipt', 'bill', 'statement', 'purchase', 'order', 'transaction', 'confirmation', 'paid']

# Dictionary to track active threads and events
active_threads = {}
stop_events = {}

def ensure_directories_exist():
    if not os.path.exists(TOKENS_FOLDER):
        os.makedirs(TOKENS_FOLDER)
    if not os.path.exists(ATTACHMENTS_FOLDER):
        os.makedirs(ATTACHMENTS_FOLDER)
    if not os.path.exists(LAST_CHECKED_FOLDER):
        os.makedirs(LAST_CHECKED_FOLDER)

def get_last_checked_time(username):
    filepath = os.path.join(LAST_CHECKED_FOLDER, f"{username}.json")
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            data = json.load(file)
            return datetime.fromisoformat(data['last_checked'])
    return datetime.now(timezone.utc) - timedelta(minutes=1)

def save_last_checked_time(username, last_checked):
    filepath = os.path.join(LAST_CHECKED_FOLDER, f"{username}.json")
    with open(filepath, 'w') as file:
        json.dump({'last_checked': last_checked.isoformat()}, file)

def save_credentials(email, server, port, username, password):
    credentials = {
        'server': server,
        'port': port,
        'username': username,
        'password': password
    }
    with open(os.path.join(TOKENS_FOLDER, f"{email}.json"), 'w') as file:
        json.dump(credentials, file)

def load_credentials():
    credentials_list = []
    for filename in os.listdir(TOKENS_FOLDER):
        if filename.endswith('.json'):
            with open(os.path.join(TOKENS_FOLDER, filename), 'r') as file:
                credentials = json.load(file)
                credentials_list.append(credentials)
    return credentials_list

def save_email_details(sender, recipient, attachment_names, email_id, urls=None):
    details = f"Sender: {sender}\nRecipient: {recipient}\nAttachments: {', '.join(attachment_names)}\n"
    if urls:
        details += f"Downloaded URLs: {', '.join(urls)}\n"
    details_path = os.path.join(ATTACHMENTS_FOLDER, f"{email_id}.txt")
    with open(details_path, 'w') as file:
        file.write(details)

def download_and_save_url(url, email_id):
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.content  # Changed to handle binary data
        # Generate a short, unique filename using a hash of the URL
        hash_object = hashlib.sha256(url.encode())
        short_filename = hash_object.hexdigest()[:16]  # Use the first 16 characters of the hash
        url_path = os.path.join(ATTACHMENTS_FOLDER, f"{email_id}_{short_filename}.pdf")
        with open(url_path, 'wb') as file:
            file.write(content)
        return url_path
    except requests.RequestException as e:
        logging.error(f"Error downloading URL {url}: {e}")
        return None

def check_keywords_in_email(msg):
    try:
        subject, encoding = decode_header(msg["Subject"])[0]
        if isinstance(subject, bytes):
            subject = subject.decode(encoding if encoding else "utf-8")
        for keyword in KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', subject, re.IGNORECASE):
                return keyword, []

        urls_to_download = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if part.get_filename():
                    filename = part.get_filename()
                    for keyword in KEYWORDS:
                        if re.search(r'\b' + re.escape(keyword) + r'\b', filename, re.IGNORECASE):
                            return keyword, []
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        body = part.get_payload(decode=True)
                        charset = part.get_content_charset() if part.get_content_charset() else "utf-8"
                        body = body.decode(charset, errors='ignore')
                        found_urls = re.findall(r'https://www\.greeninvoice\.co\.il/api/v1/documents/[^\s]+', body)
                        if found_urls:
                            urls_to_download.extend(found_urls)
                            return None, urls_to_download  # Stop searching and return URLs immediately
                        for keyword in KEYWORDS:
                            if re.search(r'\b' + re.escape(keyword) + r'\b', body, re.IGNORECASE):
                                return keyword, urls_to_download
                    except Exception as e:
                        logging.error(f"Error decoding body: {e}")
        else:
            body = msg.get_payload(decode=True)
            charset = msg.get_content_charset() if msg.get_content_charset() else "utf-8"
            try:
                body = body.decode(charset, errors='ignore')
                found_urls = re.findall(r'https://www\.greeninvoice\.co\.il/api/v1/documents/[^\s]+', body)
                if found_urls:
                    urls_to_download.extend(found_urls)
                    return None, urls_to_download  # Stop searching and return URLs immediately
                for keyword in KEYWORDS:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', body, re.IGNORECASE):
                        return keyword, urls_to_download
            except Exception as e:
                logging.error(f"Error decoding body: {e}")

        return None, urls_to_download
    except Exception as e:
        logging.error(f"Error in check_keywords_in_email: {e}")
        return None, []

def save_attachments(msg, email_id):
    attachment_names = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            if filename:
                filepath = os.path.join(ATTACHMENTS_FOLDER, filename)
                with open(filepath, 'wb') as file:
                    file.write(part.get_payload(decode=True))
                attachment_names.append(filename)
    return attachment_names

def check_inbox(imap, username):
    try:
        last_checked_time = get_last_checked_time(username)
        current_time = datetime.now(timezone.utc)

        # Select the mailbox you want to check (INBOX by default)
        imap.select("INBOX")

        # Search for emails since the last checked date
        search_criterion = f'SINCE {last_checked_time.strftime("%d-%b-%Y")}'
        logging.info(f"Search criterion: {search_criterion}")
        status, messages = imap.search(None, search_criterion)
        if status != 'OK':
            return "Failed to search emails"

        # Convert messages to a list of email IDs
        email_ids = messages[0].split()
        found_emails = False

        for email_id in email_ids:
            # Fetch the email by ID
            status, msg_data = imap.fetch(email_id, '(RFC822)')
            if status != 'OK':
                return "Failed to fetch email"
            # Get the email content
            msg = email.message_from_bytes(msg_data[0][1])

            # Check the date of the email
            msg_date = parsedate_to_datetime(msg.get('Date'))
            if msg_date.tzinfo is None:
                msg_date = msg_date.replace(tzinfo=timezone.utc)
            if not (last_checked_time < msg_date <= current_time):
                continue

            # Decode the email subject and check for keywords
            keyword, urls_to_download = check_keywords_in_email(msg)
            if urls_to_download:
                logging.info(f"Found URLs to download: {urls_to_download}")
                sender = parseaddr(msg.get("From"))[1]
                recipient = parseaddr(msg.get("To"))[1]
                attachment_names = save_attachments(msg, email_id.decode())

                # Download URLs and save them
                downloaded_urls = [download_and_save_url(url, email_id.decode()) for url in urls_to_download]

                save_email_details(sender, recipient, attachment_names, email_id.decode(), downloaded_urls)
                found_emails = True
                break  # Stop searching after finding and downloading URLs

            if keyword:
                logging.info(f"Keyword found: {keyword}")
                sender = parseaddr(msg.get("From"))[1]
                recipient = parseaddr(msg.get("To"))[1]
                attachment_names = save_attachments(msg, email_id.decode())
                save_email_details(sender, recipient, attachment_names, email_id.decode())
                found_emails = True

        # Save the current time as the last checked time
        save_last_checked_time(username, current_time)

        return found_emails
    except Exception as e:
        logging.error(f"Error in check_inbox: {e}")
        return str(e)

def continuous_check_inbox(server, port, username, password, stop_event):
    while not stop_event.is_set():
        try:
            logging.info(f"Checking inbox for {username}")
            imap = imaplib.IMAP4_SSL(server, port)
            imap.login(username, password)
            result = check_inbox(imap, username)
            if isinstance(result, str):
                logging.error(f"An error occurred: {result}")
            elif result:
                logging.info(f"New emails found with keywords for {username}")
            else:
                logging.info(f"No new emails found with keywords for {username}")
            imap.logout()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        stop_event.wait(timeout=60)

def start_all_saved_credentials():
    credentials_list = load_credentials()
    for credentials in credentials_list:
        if credentials['username'] not in active_threads:
            stop_event = Event()
            thread = Thread(target=continuous_check_inbox, args=(
                credentials['server'], credentials['port'], credentials['username'], credentials['password'], stop_event), name=credentials['username'])
            thread.daemon = True
            thread.start()
            active_threads[credentials['username']] = thread
            stop_events[credentials['username']] = stop_event

def start_checking(server, port, username, password):
    try:
        imap = imaplib.IMAP4_SSL(server, port)
        status, error = imap.login(username, password)
        if status != 'OK':
            return f"Failed to start checking inbox: {error}", 500
        imap.logout()
    except Exception as e:
        logging.error(f"Failed to start checking inbox: {e}")
        return f"Failed to start checking inbox: {e}", 500

    # Save the credentials
    ensure_directories_exist()
    save_credentials(username, server, port, username, password)

    # Start a background thread to check the inbox continuously
    if username not in active_threads:
        stop_event = Event()
        thread = Thread(target=continuous_check_inbox, args=(server, port, username, password, stop_event), name=username)
        thread.daemon = True
        thread.start()
        active_threads[username] = thread
        stop_events[username] = stop_event
        logging.info(f"Started checking inbox for {username}")
    else:
        logging.info(f"Already checking inbox for {username}")

    return "Started checking inbox", 200

def delete_credentials(email):
    tokens_file_path = os.path.join(TOKENS_FOLDER, f"{email}.json")
    last_checked_file_path = os.path.join(LAST_CHECKED_FOLDER, f"{email}.json")

    # Check if the files exist and delete them
    tokens_file_exists = os.path.exists(tokens_file_path)
    last_checked_file_exists = os.path.exists(last_checked_file_path)

    if not tokens_file_exists and not last_checked_file_exists:
        return f"Files for {email} do not exist in either folder", 404

    errors = []

    if tokens_file_exists:
        try:
            os.remove(tokens_file_path)
        except Exception as e:
            errors.append(f"Error deleting tokens file: {str(e)}")

    if last_checked_file_exists:
        try:
            os.remove(last_checked_file_path)
        except Exception as e:
            errors.append(f"Error deleting last checked file: {str(e)}")

    # Stop the thread
    if email in active_threads:
        stop_events[email].set()  # Signal the thread to stop
        active_threads[email].join()  # Wait for the thread to finish
        del active_threads[email]  # Remove from active threads
        del stop_events[email]  # Remove from stop events

    if errors:
        logging.error(f"Errors occurred during deletion: {errors}")
        return {"error": errors}, 500

    logging.info(f"Files for {email} deleted successfully")
    return f"Files for {email} deleted successfully", 200