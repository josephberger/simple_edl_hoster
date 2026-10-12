import os

from dotenv import load_dotenv

# Gunicorn reads this file before importing the app, so load .env here too
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# Loopback by default: nginx is the public face
bind = os.environ.get("GUNICORN_BIND", "127.0.0.1:8000")
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
timeout = 30

# Import the app once in the master so DB/feed initialisation and first-run
# admin seeding happen a single time, not once per worker.
preload_app = True

accesslog = "-"
errorlog = "-"
