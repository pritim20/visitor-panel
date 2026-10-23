# Visitor Management System

A single-file Flask app (`main.py`) with two dashboards:

- **Admin Panel**: register a visitor (name, company, phone, email, date of issue, expiry date, issued by). A QR pass is generated and emailed to the visitor, HR and Security. Admin can view every visitor's full history, resend the QR, or revoke a pass.
- **Security Panel**: scan the QR with the camera (or a USB scanner, or type the pass ID / phone number), then **Log IN** / **Log OUT**. Times are recorded automatically. While a visitor is inside, security adds the devices they carry (device name, model name, quantity).

History (log-in, log-out, duration, devices, which guard logged it) is visible in both panels and can be exported as CSV.

## Run

```bash
pip install -r requirements.txt
python main.py
```

Open http://127.0.0.1:5000

| Login      | Password      | Access                    |
|------------|---------------|---------------------------|
| `admin`    | `admin123`    | Admin + Security panels   |
| `security` | `security123` | Security panel only       |

Change both passwords after first login (**Password** in the top bar). Admin can add more users in **Settings**.

## Email setup (needed to send QR codes)

Admin → **Settings**: set the default HR and Security email addresses and the SMTP details, then use **Send test**.

- **Gmail**: host `smtp.gmail.com`, port `587`, username = your Gmail address, password = a Google **App Password** (requires 2-step verification; your normal password will not work).
- **Outlook / Microsoft 365**: host `smtp.office365.com`, port `587`.
- Port `465` uses SSL; any other port uses STARTTLS.

If email is not configured, the pass is still created and the QR can be downloaded from the visitor page.

## Camera scanning

Browsers only allow the camera on `https://` or `localhost`. On the security desk PC, open `http://localhost:5000`. To scan from a phone or another PC on the network, run with HTTPS:

```bash
pip install pyopenssl
VMS_HTTPS=1 python main.py        # Windows PowerShell: $env:VMS_HTTPS=1; python main.py
```

Then open `https://<server-ip>:5000` and accept the certificate warning. The scanner script loads from unpkg.com, so the browser needs internet access; manual entry and USB scanners work offline.

## Rules

- Log-in is refused if the pass is expired, revoked, or before its date of issue.
- Log-out is always allowed, so an expired visitor can still leave.
- A visitor cannot be logged in twice at the same time.

## Files created at runtime

- `visitors.db`: SQLite database (visitors, visits, devices, users, settings)
- `qr_codes/`: QR images
- `.secret_key`: session key

Back up `visitors.db` to keep the history.

## Optional environment variables

`VMS_PORT` (default 5000), `VMS_HOST` (default 0.0.0.0), `VMS_DB`, `VMS_SECRET_KEY`, `VMS_HTTPS=1`, and first-run defaults `VMS_COMPANY`, `VMS_HR_EMAIL`, `VMS_SECURITY_EMAIL`, `VMS_SMTP_HOST`, `VMS_SMTP_PORT`, `VMS_SMTP_USER`, `VMS_SMTP_PASSWORD`, `VMS_SMTP_SENDER`.
