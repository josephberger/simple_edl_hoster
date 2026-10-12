# Simple EDL Hoster

A lightweight, self-contained Flask service designed to collect, validate, and host a custom **URL External Dynamic List (EDL)** for Palo Alto Networks (PAN-OS) firewalls.

It features:
- **SQLite Database Authentication:** Uses salted password hashing (`werkzeug.security`).
- **Seed User:** On first run an `admin` user is created with a random password printed to the console (or set `EDL_ADMIN_PASSWORD`).
- **CSRF Protection & Duplicate Detection:** POSTs require a session token; repeated entries are rejected.
- **PAN-OS URL Validation:** Enforces syntax compatibility with PAN-OS URL matchers, allowing leftmost wildcards (e.g., `*.malicious.com`).
- **Inline Comment Tracking:** Appends a space and `#` to each line, recording the authenticated user and timestamp without interfering with PAN-OS list parsing.
- **Dedicated EDL Feed Endpoint:** Hosts a plain-text endpoint at `/edl/urls.txt` ready for firewall polling.

---

## 1. Quick Start

### Prerequisites
- Python 3.8+
- `pip`

### Installation
1. Clone or download the project files into a folder:
   ```bash
   mkdir simple-edl-hoster && cd simple-edl-hoster
   ```
   Required files: `simple_edl_hoster.py`, `gunicorn.conf.py`, `requirements.txt`, `.env`, `feeds/`.
2. Save `simple_edl_hoster.py` in this directory.
3. Install required packages:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

### Configuration
Copy `.env_example` to `.env` and fill it in (a ready-made `.env` is already here; it's git-ignored):

| Variable | Purpose |
|---|---|
| `FLASK_SECRET_KEY` | Session signing key (`openssl rand -hex 32`); same for all workers |
| `EDL_ADMIN_PASSWORD` | Password for `admin`, applied only when the user table is empty (first run) |
| `EDL_HOST` / `EDL_PORT` | Bind address and port (default `0.0.0.0:5500`) |
| `EDL_FEED_DIR` | Folder holding feed files (default `feeds`) |

### Running the Application (testing)
```bash
source .venv/bin/activate
python simple_edl_hoster.py
```
This uses Flask's built-in development server (`EDL_HOST`/`EDL_PORT`). For anything real, use the production setup in section 5.
On initial start, the application will automatically:
- Create `edl_users.db`
- Seed the `admin` account with a random password, printed once to the console (override with `EDL_ADMIN_PASSWORD`)
- Create the `feeds/` folder (a sample `feeds/urls.txt` ships with the project)

---

## 2. Usage

### Web UI
1. Navigate to: `http://<SERVER_IP>:5500/login`
2. Log in as `admin` with the password printed at first start.
3. Submit URLs or wildcard domains. Acceptable syntax examples:
   - `*.threatactor.net`
   - `phishing.evilcorp.com/login.php`
   - `malicious-domain.co.uk`
   - `*.subdomain.evil.org:8080/path`

### Multiple Feeds
Every `*.txt` file in `feeds/` is its own feed, served without authentication at `/edl/<name>.txt`:

| File | Firewall Source URL |
|---|---|
| `feeds/urls.txt` | `http://<SERVER_IP>:5500/edl/urls.txt` |
| `feeds/phishing.txt` | `http://<SERVER_IP>:5500/edl/phishing.txt` |

To add a feed, create an empty or commented `.txt` file in `feeds/` (names: letters, digits, `-`, `_`). It appears in the web UI's feed dropdown immediately, no restart needed. Create one PAN-OS EDL object per feed.

### Feed Format
Each feed file records entries line-by-line using standard PAN-OS EDL comment structure:

```text
# Palo Alto Networks Custom EDL URL Feed
*.threatactor.net # added by admin on 2026-10-12 17:15:00 UTC
phishing.evilcorp.com/login.php # added by admin on 2026-10-12 17:16:22 UTC
```

> **Note on PAN-OS Comment Parsing:** Per Palo Alto Networks EDL specifications, any line beginning with `#` or any text following a space and hash character (` #`) is treated as a comment and ignored during compilation into firewall policies.

---

## 3. Palo Alto Networks (PAN-OS) Configuration

### Step 1: Create the External Dynamic List Object
1. Log in to the **PAN-OS Web UI** (or Panorama).
2. Go to **Objects** > **External Dynamic Lists**.
3. Click **Add**:
   - **Name:** `Custom-Block-URLs`
   - **Type:** `URL List`
   - **Source URL:** `http://<YOUR_SERVER_IP>:5500/edl/urls.txt` (or your HTTPS reverse-proxy URL)
   - **Recurring:** Set your preferred poll interval (e.g., *Five Minute* or *Hourly*).
4. Click **OK** and **Commit** the changes.

### Step 2: Reference in URL Filtering or Security Policy
- **URL Filtering Profile:** Add the EDL object to the profile's **Block List** or assign an action in **URL Categories**.
- **Security Rule:** Create a Security Policy rule referencing the EDL under the **Service/URL Category** tab.

### Step 3: Verify and Test via Firewall CLI
Run the following CLI commands on the firewall to inspect pickup:

```text
# Check status and downloaded count
request system external-list show type url name Custom-Block-URLs

# Force an immediate refresh
request system external-list refresh type url name Custom-Block-URLs

# View the entries compiled on the firewall
request system external-list view type url name Custom-Block-URLs
```

---

## 4. Production Hardening Recommendations

1. **Change the Admin Password:**
   Update the `admin` password via a quick script or SQLite command:
   ```python
   import sqlite3
   from werkzeug.security import generate_password_hash

   conn = sqlite3.connect("edl_users.db")
   new_hash = generate_password_hash("YourSecurePasswordHere", method="pbkdf2:sha256")
   conn.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (new_hash,))
   conn.commit()
   conn.close()
   ```

2. **Environment Secret Key:**
   Set the Flask session key via environment variable (required with multiple workers, otherwise each gets a random key):
   ```bash
   export FLASK_SECRET_KEY="$(openssl rand -hex 32)"
   ```

3. **Run under gunicorn behind a TLS reverse proxy** - see section 5.
   Firewalls should ideally query the feed over HTTPS with valid certificates.

---

## 5. Production Deployment

Gunicorn is used because this is a Flask (WSGI) app; uvicorn targets ASGI frameworks and would add nothing here.

### Run gunicorn manually
Settings live in `gunicorn.conf.py` and `.env` (`GUNICORN_BIND`, `GUNICORN_WORKERS`). By default it binds to `127.0.0.1:5500`, so only the local reverse proxy can reach it. Set `GUNICORN_BIND=0.0.0.0:5500` to listen on all interfaces (no TLS unless something else provides it).
```bash
source .venv/bin/activate
gunicorn simple_edl_hoster:app
```
The app is preloaded once in the master process, so database setup and admin seeding happen a single time. Feed writes use a cross-process file lock (`.feed.lock`), so multiple workers are safe. Note that the first-run admin password is the one in `.env`.

### systemd service
Create a service user and put the app in `/opt/simple-edl-hoster` (adjust paths to taste):
```bash
sudo useradd --system --home /opt/simple-edl-hoster --shell /usr/sbin/nologin edl
sudo mkdir -p /opt/simple-edl-hoster && sudo cp -r . /opt/simple-edl-hoster/
cd /opt/simple-edl-hoster && sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
sudo chown -R edl:edl /opt/simple-edl-hoster && sudo chmod 600 /opt/simple-edl-hoster/.env
```

`/etc/systemd/system/simple-edl-hoster.service`:
```ini
[Unit]
Description=PAN-OS Simple EDL Hoster (gunicorn)
After=network.target

[Service]
User=edl
Group=edl
WorkingDirectory=/opt/simple-edl-hoster
ExecStart=/opt/simple-edl-hoster/.venv/bin/gunicorn simple_edl_hoster:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/simple-edl-hoster

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now simple-edl-hoster
sudo systemctl status simple-edl-hoster
journalctl -u simple-edl-hoster -f      # logs
```

### nginx with SSL in front (high level)
1. Keep gunicorn on loopback (`GUNICORN_BIND=127.0.0.1:5500`) so it is not reachable from the network.
2. Install nginx and obtain a certificate, e.g. Let's Encrypt (`sudo certbot --nginx -d edl.example.com`) or your internal CA.
3. Add a server block that terminates TLS and proxies to gunicorn, `/etc/nginx/sites-available/simple-edl-hoster`:
   ```nginx
   server {
       listen 80;
       server_name edl.example.com;
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl;
       server_name edl.example.com;

       ssl_certificate     /etc/letsencrypt/live/edl.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/edl.example.com/privkey.pem;

       location / {
           proxy_pass http://127.0.0.1:5500;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
   ```bash
   sudo ln -s /etc/nginx/sites-available/simple-edl-hoster /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```
4. In `.env`, set `EDL_BEHIND_PROXY=1` and `EDL_COOKIE_SECURE=1`, then `sudo systemctl restart simple-edl-hoster`. The first makes the app trust nginx's forwarded headers; the second marks the session cookie HTTPS-only.
5. Point the firewall EDL objects at `https://edl.example.com/edl/<name>.txt`. The firewall must trust the certificate's CA (import it under Device > Certificate Management if it's an internal CA).
6. Optionally restrict who can reach `/edl/` or the UI in nginx with `allow`/`deny` rules, since the feeds are unauthenticated by design.
