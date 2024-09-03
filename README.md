# LE-Chat-PHP Scraper Script

This Python script is designed to scrape chat messages and notes from [Le-Chat-php](https://github.com/DanWin/le-chat-php) based chats, handle session keepalive to avoid timeouts, and send email alerts in case of connectivity issues.
It also supports logging and environment variable management using `.env` files.

## Features

- Scrapes messages from different chat channels.
- Extracts and displays chatters, messages, and notes.
- Periodically sends keepalive messages to prevent session expiration.
- Sends email alerts in case of connectivity issues.
- Logs activities and errors.
- Supports customizable settings via environment variables.

## Requirements

- Python 3.x
- Required Python packages: `rich`, `requests`, `beautifulsoup4`, `python-dotenv`

You can install the required packages using:

```bash
pip instarr -r ./requirements.txt
```

