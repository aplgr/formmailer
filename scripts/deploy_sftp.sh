#!/usr/bin/env bash
set -euo pipefail

# Simple SFTP deploy script template. Replace host/user/paths with your values.
HOST="sshXXXX.host.tld"
USER="u000000"
REMOTE_ROOT="/www/htdocs/u000000/api.example.com"

echo "» Deploying formmailer CGI…"
sftp -q "${USER}@${HOST}" <<'SFTP'
cd /www/htdocs/u000000/api.example.com/cgi-bin
put -p cgi-bin/contact.py
chmod 755 contact.py

cd /www/htdocs/u000000/api.example.com/cgi-bin
put -p cgi-bin/.htaccess .htaccess

# Only put your real env file if you knowingly want to upload secrets this way.
# Otherwise, copy contact.env.example to contact.env on the server and edit there.
# put -p cgi-bin/contact.env contact.env
# chmod 600 contact.env
SFTP

echo "Done."
