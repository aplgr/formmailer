# formmailer

A tiny **CGI form mailer**: receive form submissions over HTTP and deliver via SMTP.
Modern but dependency‑free: JSON `POST`, CORS allow‑list, honeypot, minimum fill time, and per‑IP rate limiting.
Designed to work on simple shared hosting with CGI enabled.

## Features
- JSON API (`application/json`) with strict content handling and request size limit
- CORS with explicit allow‑list (origins in env file)
- Honeypot field, minimum fill time, simple per‑IP rate limit (file‑based)
- Safe mail headers: `From` = your mailbox (passes SPF/DKIM/DMARC), `Reply-To` = visitor
- TLS via STARTTLS (587) or SMTPS (465)
- No external Python packages

## Quick start (shared hosting with CGI)
1. Upload **`cgi-bin/contact.py`** and make it executable:
   ```bash
   chmod 755 cgi-bin/contact.py
   ```
2. Copy **`cgi-bin/contact.env.example`** to **`cgi-bin/contact.env`**, set your values, and protect it:
   ```bash
   chmod 600 cgi-bin/contact.env
   ```
3. Place **`cgi-bin/.htaccess`** next to `contact.py` (enables CGI and denies access to `contact.env`).
4. Add a rewrite rule in your **web root** to map `/contact` to the CGI. Use `examples/webroot.htaccess` as a template.
5. Ensure your API subdomain (e.g., `api.example.com`) has TLS enabled.
6. Test from your machine:
   ```bash
   curl -i -X OPTIONS https://api.example.com/contact          -H 'Origin: https://www.example.com'          -H 'Access-Control-Request-Method: POST'          -H 'Access-Control-Request-Headers: Content-Type'

   curl -i -X POST https://api.example.com/contact          -H 'Origin: https://www.example.com'          -H 'Content-Type: application/json'          --data '{"name":"Test","email":"test@example.org","subject":"Hello","message":"Ping","_elapsed_ms":"6000"}'
   ```

### Environment variables (`cgi-bin/contact.env`)
```env
# SMTP
SMTP_HOST=mail.example.com
SMTP_TLS_MODE=starttls   # starttls | ssl
SMTP_PORT=587            # 465 when SMTP_TLS_MODE=ssl
SMTP_USER=hello@example.com
SMTP_PASS=please-change-me
TO_ADDR=hello@example.com

# CORS
ALLOWED_ORIGINS=https://example.com,https://www.example.com

# Guards
MIN_ELAPSED_MS=5000      # minimum time user spent on the form (client also sends _elapsed_ms)
MIN_INTERVAL_S=30        # per-IP cooldown, file-based

# DoS guard
MAX_BODY=65536           # request body size limit in bytes
```

## Frontend example (Alpine.js + htmx)
See `examples/partials_contact.html` and `examples/assets/js/contact.js` for a minimal integration.
The form is progressive‑enhancement friendly: if JS is disabled, your fallback action still applies.

## Security notes
- The script strictly requires `application/json` and rejects oversized bodies.
- Header sanitization prevents header injection.
- `contact.env` must **not** be world‑readable and is denied in `.htaccess`.
- Configure SPF, DKIM and DMARC for your domain; keep `From` = your domain mailbox.
- Rate limiting is basic and file‑based; add a WAF/Reverse‑Proxy limit if you need more.

## License
MIT — see `LICENSE`.
