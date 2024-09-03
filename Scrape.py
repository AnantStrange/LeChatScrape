#! /usr/bin/env python3

from rich.markup import escape as rich_escape
import re
import csv
import argparse
import threading
import os
from typing import Dict, List, Optional, Set, Tuple, Union, cast
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests, time
from bs4 import BeautifulSoup as bs, Tag
from rich import print as pprint
import logging
import os
from dotenv import load_dotenv

load_dotenv()

PROXIES = {
    "http": os.getenv("HTTP_PROXY"),
    "https": os.getenv("HTTPS_PROXY")
}

SESSION = os.getenv("SESSION", "default_value")
URL = os.getenv("URL", "default_value")

TO_EMAIL = os.getenv("TO_EMAIL", "default_value")
FROM_EMAIL = os.getenv("FROM_EMAIL", "default_value")
SMTP_SERVER = os.getenv("SMTP_SERVER", "default_value")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "default_value")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "default_value")

CHATLOG = os.getenv("CHATLOG", "default_value")
SCRIPTLOG = os.getenv("SCRIPTLOG", "default_value")


# Configure logging at the beginning of your script
logging.basicConfig(
    filename=SCRIPTLOG,  # Name of the log file
    level=logging.INFO,        # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(levelname)s - %(filename)s - Line: %(lineno)d - %(message)s',
    filemode='a'                # Open the log file in append mode
)

def sanitize_message(message):
    """Sanitizes the message by Remove [M], [A], [S] or ℹ️ prefix from system messages"""
    message = re.sub(r'^\[(M|A|S)\]', '', message).strip()  # Remove [M], [A], [S]
    message = re.sub(r'^\s*ℹ️\s*', '', message).strip()    # Remove ℹ️ prefix
    return message

def start_new_run():
    """Write a timestamp separator to the log file."""
    with open(SCRIPTLOG, 'a') as log_file:
        log_file.write("\n\n###### {} ######\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    logging.info("Script started.")


def send_email(subject: str, body: str, to_email: str, from_email: str, smtp_server: str, smtp_port: int, smtp_user: str, smtp_password: str):
    """
    Sends an email notification.
    """
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            print("Alert email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def check_connectivity():
    """
    Checks internet and Tor connectivity.
    """
    try:
        # Check internet connectivity
        requests.get('https://www.google.com', timeout=5)
        # Check Tor connectivity
        requests.get('http://blkhatjxlrvc5aevqzz5t6kxldayog6jlx5h7glnu44euzongl4fh5ad.onion', proxies=PROXIES, timeout=5)
    except requests.RequestException as e:
        send_email(
            subject="Script Alert - Connectivity Issue",
            body=f"The script is unable to connect to the internet or Tor network.\n\nError: {e}",
            to_email=TO_EMAIL,
            from_email=FROM_EMAIL,
            smtp_server=SMTP_SERVER,
            smtp_port=SMTP_PORT,
            smtp_user=SMTP_USER,
            smtp_password=SMTP_PASSWORD
        )
        exit(1)


class ChatPage:
    MessageList = List[Tuple[str, Dict[str, str | bool]]]
    MessageDict = Dict[str, Dict[str, Union[str, bool]]]
    ChattersDict = Dict[str, List[Dict[str, str]]]
    NotesList = List[Dict[str, str]]

    def __init__(self, base_url: str, session_id: str, proxies: Optional[Dict[str, str]] = None):
        """
        Initializes the ChatPage object with the base URL, session ID, and proxy settings.

        Args:
        - base_url (str): The base URL of the chat service.
        - session_id (str): The session ID for the chat.
        - proxies (Dict[str, str]): Proxy settings for the HTTP session.
        
        Returns:
        - None
        """
        self.base_url = base_url
        self.session_id = session_id

        self.url = f"{base_url}/index.php?action=view&session={session_id}"
        self.post_url = f"{base_url}/index.php?action=post&session={session_id}"
        self.notes_url = f"{base_url}/index.php?action=viewpublicnotes&session={session_id}"
        self.personal_notes_url = f"{base_url}/index.php?action=notes&session={session_id}"

        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)
        self.seen_timestamps: Set = set()

        self.messages: List[Tuple[str, Dict[str, Union[str, bool]]]] = []
        self.chatters: ChatPage.ChattersDict = {}
        self.notes: ChatPage.NotesList = []
        self.personal_notes: str = ""

        # self.soup: Optional[bs] = None
        self.soup: bs
        self.notes_soup: Optional[bs] = None
        self.personal_notes_soup: Optional[bs] = None

    class ScrapeError(Exception):
        """
        Exception raised for errors during scraping.
        """
        pass

    class SessionExpired(Exception):
        """
        Exception raised for Session expired.
        """
        pass

    def clear_screen(self):
        """
        Clears the terminal screen based on the operating system.

        Returns:
        - None
        """
        os.system('cls' if os.name == 'nt' else 'clear')

    def scrape(self, page_type: str) -> None:
        """
        Fetches the page content and parses it into a BeautifulSoup object.

        Args:
        - page_type (str): The type of page to scrape ("mainpage", "postpage", "publicnotes", "personalnotes").

        Returns:
        - None

        Raises:
        - Exception: If there is an error during the HTTP request or parsing.
        """
        try:
            match page_type:
                case "mainpage":
                    response = self.session.get(self.url)
                    response.raise_for_status()
                    self.soup = bs(response.text, 'html.parser')
                case "postpage":
                    response = self.session.get(self.post_url)
                    response.raise_for_status()
                    self.post_soup = bs(response.text, 'html.parser')
                case "publicnotes":
                    response = self.session.get(self.notes_url)
                    response.raise_for_status()
                    self.notes_soup = bs(response.text, 'html.parser')
                case "personalnotes":
                    response = self.session.get(self.personal_notes_url)
                    response.raise_for_status()
                    self.personal_notes_soup = bs(response.text, 'html.parser')
        except Exception as e:
            raise e
        return


    def extractUsers(self) -> None:
        """
        Extracts chatters from the page and updates the internal chatters dictionary.

        Returns:
        - None

        Raises:
        - ScrapeError: If page content is not loaded or if the chatters container is not found.
        """
        if self.soup is None:
            raise self.ScrapeError("No page content to extract chatters from. Call scrape() first.")

        chatters_div = self.soup.find(id="chatters")
        if not isinstance(chatters_div, Tag):
            raise self.ScrapeError("Could not find Chatters Div with id #chatters in the page")

        roles: List[str] = ["Admin", "Staff", "Members", "Guests"]
        self.chatters = {role: [] for role in roles}
        current_role: Optional[str] = None

        # Iterate over all <tr> elements in the chatters_div
        for row in chatters_div.find_all('tr'):
            # Iterate over all <th> and <td> elements in the row
            for cell in row.find_all(['th', 'td']):
                # Check if the cell is a <th> and if it contains a role name
                if cell.name == 'th' and cell.text.strip().strip(':') in roles:
                    current_role = cell.text.strip().strip(':')
                # Check if the cell is a <td> and if a role has been set
                if cell.name == 'td' and current_role:
                    # Extract chatters from <a> elements with class 'nicklink'
                    for a in cell.find_all('a', class_='nicklink'):
                        span = a.find('span')
                        color = cast(str,span.get('style', ''))
                        color = color.split('color:')[-1].split(';')[0] if span else '#000000'
                        dct: Dict[str, str] = {'username': a.text.strip(), 'color': color}
                        self.chatters[current_role].append(dct)

        return

    def extractMessages(self) -> MessageDict:
        """
        Extracts new messages from the current page content and updates the internal message list.

        This method:
        1. Checks if the page content is loaded.
        2. Finds and processes messages from the page.
        3. Updates `self.all_messages` with new messages and sorts them by timestamp.
        4. Updates `self.seen_timestamps` to include timestamps of the newly extracted messages.

        Returns:
        - A dictionary of new messages extracted from the current page.

        Raises:
        - `ScrapeError`: If page content is not loaded or if the message container is not found.
        """

        if self.soup is None:
            raise self.ScrapeError("No page content to extract messages from. Call scrape() first.")

        messages_div = self.soup.find(id="messages")
        if not isinstance(messages_div, Tag):
            raise self.ScrapeError("Could not find Message Div with id #messages in the page")

        new_messages = {}

        for msg_div in messages_div.find_all('div', class_='msg'):
            timestamp_tag = msg_div.find('small')
            if not timestamp_tag:
                raise self.ScrapeError("Could not find Message timestamp")
            timestamp = timestamp_tag.text.strip().rstrip('-')

            if timestamp in self.seen_timestamps:
                continue

            usermsg_span = msg_div.find('span', class_='usermsg')
            sysmsg_span = msg_div.find('span', class_='sysmsg')

            if usermsg_span:
                isPM = '[' in usermsg_span.text and ' to ' in usermsg_span.text
                if isPM:
                    parts = usermsg_span.text.split('] - ')
                    if len(parts) == 2:
                        user_part = parts[0].lstrip('[')
                        message_part = parts[1].strip()

                        sender_span = usermsg_span.find('span', style=True)
                        sender = sender_span.text.strip() if sender_span else user_part.split(' to ')[0].strip()

                        recipient_span = usermsg_span.find_all('span', style=True)[1] if len(usermsg_span.find_all('span', style=True)) > 1 else None
                        recipient = recipient_span.text.strip() if recipient_span else user_part.split(' to ')[1].strip()

                        message = message_part
                        new_messages[timestamp] = {
                            'from': sender,
                            'to': recipient,
                            'message': message,
                            'isPM': True,
                            'isDeleted': False,
                            'channel': 'personal'
                        }
                else:
                     # Determine the channel based on the prefix
                    if '[M]' in usermsg_span.text:
                        channel = 'member'
                        username = usermsg_span.text.replace('[M]', '').split('-')[0].strip()
                    elif '[S]' in usermsg_span.text:
                        channel = 'staff'
                        username = usermsg_span.text.replace('[S]', '').split('-')[0].strip()
                    elif '[A]' in usermsg_span.text:
                        channel = 'admin'
                        username = usermsg_span.text.replace('[A]', '').split('-')[0].strip()
                    else:
                        channel = 'guest'
                        username = cast(Tag, usermsg_span.find('span')).text.strip()

                    message = usermsg_span.text.replace(username, '').replace('-', '').strip()
                    new_messages[timestamp] = {
                        'from': username,
                        'to': 'everyone',
                        'message': message,
                        'isPM': False,
                        'isDeleted': False,
                        'channel': channel
                    }

            elif sysmsg_span:
                message = sysmsg_span.text.strip()
                new_messages[timestamp] = {
                    'from': 'System',
                    'to': 'everyone',
                    'message': message,
                    'isPM': False,
                    'isDeleted': False,
                    'channel': 'system'
                }

        # Update seen timestamps and extend all_messages with new messages
        self.seen_timestamps.update(new_messages.keys())
        self.messages.extend(sorted(new_messages.items()))  # Ensure all_messages is sorted
        self.messages.sort(key=lambda x: x[0])  # Sort messages by timestamp

        return new_messages


    def extractNotes(self) -> None:
        """
        Extracts new notes from the current page content and updates the internal note list.

        Returns:
        - None

        Raises:
        - `ScrapeError`: If page content is not loaded or if the message container is not found.
        """
        if self.notes_soup is None:
            raise self.ScrapeError("No page content to extract notes from. Call scrape_notes() first.")

        notes = []
        for note in self.notes_soup.find_all('textarea'):
            previous_text = note.find_previous_sibling(text=True).strip()
            username, timestamp = previous_text.split(' at ', 1)
            username = username.replace('Last edited by ', '')
            timestamp = timestamp.strip()
            note_text = note.text.strip()
            notes.append({
                'username': username,
                'timestamp': timestamp,
                'note': note_text
            })
        self.notes = notes
        return

    def extractPersonalNotes(self):
        if self.personal_notes_soup is None:
            raise self.ScrapeError("No page content to extract notes from. Call scrape_notes() first.")

        # Find the textarea containing the personal notes
        textarea = self.personal_notes_soup.find('textarea', {'name': 'text'})
        if textarea:
            self.personal_notes = textarea.text.strip()
        else:
            self.personal_notes = ""
        return

    def displayMessages(self, new_messages: MessageDict) -> None:
        """
        Displays new messages in a formatted manner.

        Args:
        - new_messages (MessageDict): Dictionary of new messages to display.

        Returns:
        - None
        """
        sorted_messages = sorted(new_messages.items(), key=lambda x: x[0])
        for timestamp, msg in sorted_messages:
            escaped_message = rich_escape(msg['message'])
            if msg['isPM']:
                formatted_message = f"[bold yellow]{timestamp}[/bold yellow] - [bold cyan][{msg['from']} to {msg['to']}][/bold cyan] : [bold green]{escaped_message}[/bold green]"
            else:
                formatted_message = f"[bold yellow]{timestamp}[/bold yellow] - [bold cyan]{msg['from']}[/bold cyan]: [bold green]{escaped_message}[/bold green]"
            pprint(formatted_message)  # Use pprint from rich
        return



    def displayNotes(self) -> None:
        """
        Displays Notes in a formatted manner.

        Returns:
        - None
        """

        for note in self.notes:
            formatted_note = f"[bold yellow]{note['timestamp']}[/bold yellow] - [bold cyan]{note['username']}[/bold cyan]: [bold green]{note['note']}[/bold green]"
            pprint(formatted_note)

    def printChatters(self) -> None:
        """
        Prints the current chatters grouped by their roles.

        Returns:
        - None
        """
        for role, users in self.chatters.items():
            if not users:
                pprint(f"{role}: No chatters")
            else:
                formatted_users = [
                    f"[{user['color']}]{user['username']}[{user['color']}]"
                    for user in users
                ]
                string = f"{role}: {' '.join(formatted_users)}"
                pprint(string)
                return

    def keepalive(self, abortsignal, interval: int = 1200) -> None:
        """
        Sends a keepalive message periodically to prevent session timeout.

        Args:
        - abortsignal: A signal used to check if the keepalive process should be terminated.
        - interval (int): Time in seconds between keepalive messages. Defaults to 1200 seconds (20 minutes).

        Returns:
        - None
        """
        logging.info("Keepalive thread started.")
        last_sent_time = time.time()
        while not abortsignal.is_set():
            current_time = time.time()
            if current_time - last_sent_time >= interval:
                try:
                    self.scrape("postpage")
                    hidden_inputs = self.post_soup.find_all("input", type="hidden")
                    values = [input_elem['value'] for input_elem in hidden_inputs]
                    if len(values) < 5:
                        raise ValueError("Not enough hidden input values found.")

                    nc = values[1]
                    postid = values[4]
                    
                    # Send a keepalive message
                    data = {
                        'action': 'post',
                        'session': self.session_id,
                        'message': "<keepalive>",
                        'multi': '',
                        'lang': 'en',
                        'sendto': '0',
                        'nc': nc,
                        'postid': postid
                    }
                    
                    # Perform the POST request to send the keepalive message
                    response = self.session.post(self.base_url, data=data)
                    response.raise_for_status()
                    logging.info("Keepalive message sent successfully.")
                    last_sent_time = current_time  # Update the time after sending

                except Exception as e:
                    logging.error(f"Keepalive POST ERROR: {e}")

            time.sleep(1)  # Short sleep to check abortsignal frequently

        logging.info("Keepalive thread received abort signal. Shutting down.")


        

    def verify_session(self) -> None:
        self.scrape("postpage")
        if not self.post_soup.find("tr", {"id": "firstline"}):
            send_email(
                subject="Script Alert - Session Expired",
                body="The script's session has expired. Please update the session ID.",
                to_email=TO_EMAIL,
                from_email=FROM_EMAIL,
                smtp_server=SMTP_SERVER,
                smtp_port=SMTP_PORT,
                smtp_user=SMTP_USER,
                smtp_password=SMTP_PASSWORD,
            )
            print("Session expired. Notification sent.")
            logging.error("Session expired. Notification sent.")
            raise self.SessionExpired()




    def run(self, interval: int = 5, log_filename: Optional[str] = None):
        """
        Continuously fetches, updates, prints chat data every <interval> seconds,
        logs messages to a text file, and saves a CSV for easier parsing.

        Args:
        - interval (int): Time in seconds between each scrape. Defaults to 5 seconds.
        - log_filename (Optional[str]): Base filename for the logs (text and CSV).

        Returns:
        - None

        Raises:
        - KeyboardInterrupt: If the user interrupts the process with Ctrl+C.
        """
        abort_event = threading.Event()  # Create an event for signaling termination

        try:
            self.verify_session()
            keepalive_thread = threading.Thread(target=self.keepalive, args=(abort_event,))
            keepalive_thread.start()
        except self.SessionExpired:
            print("Session expired. Exiting...")
            logging.error("Session expired. Exiting...")
            exit(1)

        if log_filename:
            txt_filename = f"{log_filename}.txt"
            csv_filename = f"{log_filename}.csv"
        else:
            txt_filename = os.devnull
            csv_filename = os.devnull

        try:
            with open(txt_filename, 'a') as log_file, open(csv_filename, 'a', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                
                # Write CSV header if the file is empty
                if os.path.getsize(csv_filename) == 0:
                    csv_writer.writerow(['Timestamp', 'From', 'To', 'Message', 'isPM', 'isDeleted', 'Channel'])

                if log_filename:
                    # Add timestamp separation in the log file
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write("\n\n######### {} ######\n\n".format(current_time))

                while True:
                    try:
                        self.verify_session()
                    except self.SessionExpired:
                        print("Session expired. Exiting...")
                        logging.error("Session expired. Exiting...")
                        exit(1)

                    self.scrape("mainpage")
                    new_messages = self.extractMessages()

                    if new_messages:
                        self.displayMessages(new_messages)

                        for timestamp, msg in sorted(new_messages.items()):
                            formatted_message = (
                                f"{timestamp} - [{msg['from']} to {msg['to']}] : {msg['message']}\n"
                                if msg['isPM']
                                else f"{timestamp} - {msg['from']}: {msg['message']}\n"
                            )
                            log_file.write(formatted_message)
                            # log_file.flush()  # Ensure the buffer is flushed

                            sanitized_message = sanitize_message(msg['message'])
                            csv_writer.writerow([
                                timestamp.strip(), msg['from'], msg.get('to', ''), sanitized_message, 
                                msg['isPM'], msg['isDeleted'], msg['channel']
                            ])

                        time.sleep(interval)

        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting...")

        finally:
            # Signal the keepalive thread to stop and wait for it to finish
            abort_event.set()
            keepalive_thread.join()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Page Scraper")
    parser.add_argument("-s", "--session", help="Session ID for the chat",default=SESSION)
    parser.add_argument("-u", "--base_url", help="Base URL for the chat page", default=URL)
    parser.add_argument("-so", "--socks", action="store_true", help="Use SOCKS proxy for the session (Optional)")
    parser.add_argument("-cl", "--chatlog", help="Filename for chat log (optional)", default=CHATLOG)
    parser.add_argument("-sl", "--scriptlog", help="Proxies for the session (optional)", default=SCRIPTLOG)

    args = parser.parse_args()

    start_new_run()
    check_connectivity()
    chat_page = ChatPage(base_url=args.base_url, session_id=args.session, proxies=PROXIES)

    chat_page.run(log_filename=args.chatlog)
