# Email Spoofing / SMTP Open-Relay Tester

This project checks whether a mail server is mis-configured as an **open
relay** — i.e. whether it will accept and deliver mail with an arbitrary,
unauthenticated `From` address. It is based on the original
[`emailspoofing`](https://github.com/balaganeshcyber/Emailspoofing) project
by GBHacker/Astra Cybersecurity.

Email spoofing is the technique of delivering forged email to recipients.
Attackers abuse publicly reachable, mis-configured ("open relay") SMTP
servers to send spoofed mail for phishing, spam, or persistent
"legitimate-looking" backdoors. See:
https://gbhackers.com/email-spoofing-exploiting-open-relay/

## ⚠️ Authorized use only

Only point this tool at mail servers **you own or are explicitly
authorized to test** (e.g. as part of an approved penetration test, red
team engagement, or CTF). Sending spoofed email to real third-party
recipients without authorization is abuse, can violate anti-spam/computer
misuse laws, and is out of scope for this tool. The GUI requires you to
tick an authorization checkbox before it will send anything.

## What's included

| File | Description |
|---|---|
| `smtprelay.py` | Command-line tool (interactive or fully scriptable via flags). |
| `smtprelay_gui.py` | Graphical (Tkinter) version with the same functionality. |

Both tools:
- Build a proper RFC 5322 message (correct `From`, `To`, `Cc`, `Subject`,
  `Date`, `Message-ID` headers) instead of a hand-built, header-incomplete
  string.
- Validate addresses and required fields before attempting to send.
- Support plaintext, STARTTLS, and implicit TLS/SSL (SMTPS) connections.
- Support optional SMTP `AUTH LOGIN` credentials, for servers that require
  authentication before accepting relay (useful for testing relay rules
  that only apply to unauthenticated senders).
- Report whether the server actually accepted the message for *all*
  recipients (a real open-relay finding) versus refusing some/all of them,
  instead of assuming success just because `sendmail()` didn't raise.
- Use connection timeouts and give specific, actionable error messages
  (DNS failure, connection refused, auth failure, recipients refused,
  etc.) instead of swallowing every error as "an unexpected error
  occurred."

## Requirements

- Python 3.8+
- Standard library only: `smtplib`, `email`, `ssl`, `socket`, `argparse`
  (CLI), and `tkinter` (GUI only — included with most Python installs; on
  Debian/Ubuntu install it with `sudo apt-get install python3-tk` if
  missing).

## Usage — GUI

```bash
python3 smtprelay_gui.py
```

Fill in the target server, security mode (none/STARTTLS/implicit TLS),
optional AUTH credentials, the spoofed `From` address, recipients, subject
and body, tick the authorization checkbox, and click **Send Test Email**.
Results (accepted / refused / connection errors) are shown in the log
pane at the bottom. Sending runs on a background thread so the UI never
freezes.

## Usage — CLI

Interactive mode (prompts for each field, same flow as the original
script, now with proper headers and validation):

```bash
python3 smtprelay.py
```

Non-interactive / scriptable mode:

```bash
python3 smtprelay.py \
  --server smtp.example.com --port 25 \
  --from "attacker@example.com" \
  --to "victim@example.com" \
  --subject "Test" \
  --body "This is an authorized open-relay test." \
  --yes
```

Useful flags:

- `--starttls` / `--ssl` — use STARTTLS or implicit TLS instead of plaintext.
- `--username` / `--password` — authenticate before sending (password is
  prompted securely if omitted).
- `--cc` — additional comma-separated Cc recipients.
- `--timeout` — connection timeout in seconds (default 15).
- `--verbose` — print the raw SMTP protocol exchange.
- `--yes` — skip the confirmation prompt (for scripted/CI use in an
  authorized test).

Run `python3 smtprelay.py --help` for the full list.

## Interpreting results

- **Accepted for all recipients** → the server relayed/accepted mail from
  an unauthenticated or spoofed sender. Flag this as an open-relay finding
  if that behavior wasn't intended.
- **Some/all recipients refused** → the server is enforcing relay
  restrictions for those addresses/domains; not an open-relay finding for
  that recipient.
- **Connection/auth errors** → the server wasn't reachable on that
  port/security mode, or rejected the supplied credentials.
