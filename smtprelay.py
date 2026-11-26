#!/usr/bin/env python3
"""
SMTP Open-Relay Spoofing Tester (CLI)
======================================

A diagnostic tool for AUTHORIZED security testing of mail servers to check
whether they are mis-configured as an "open relay" (i.e. they will relay or
accept mail with an arbitrary, unauthenticated From/Sender address).

Legal / ethical notice
-----------------------
Only run this against mail infrastructure you own or are explicitly
authorized to test (e.g. as part of an approved penetration test or CTF).
Sending spoofed mail to third parties without authorization is abuse and,
in many jurisdictions, illegal.

Fixes vs. the original script
------------------------------
- Proper RFC 5322 message construction via `email.message` (Subject, Date,
  Message-ID, MIME headers) instead of a hand-built string with no Subject.
- Real success/failure detection: `sendmail()` returning without raising
  does not guarantee delivery to every recipient, so the dict of refused
  recipients it returns is now checked.
- Input validation (non-empty addresses, at least one recipient, basic
  syntax check) instead of silently sending malformed mail.
- Configurable port, implicit TLS (SMTPS), STARTTLS, and optional
  AUTH LOGIN credentials for servers that require authentication.
- Sensible timeouts and specific exception handling (connection refused,
  DNS failure, auth failure, recipients refused) with clear messages and
  correct process exit codes, instead of a bare `except Exception`.
- `argparse`-based non-interactive mode (useful for scripting/CI in an
  authorized test) alongside the original interactive prompts.
- CC support and a `--yes` flag to skip the confirmation prompt only when
  explicitly requested.
"""

import argparse
import smtplib
import socket
import ssl
import sys
from datetime import datetime
from email.message import EmailMessage
from email.utils import make_msgid, formatdate, getaddresses

BANNER = r"""
   ____                         ____         __                 ______ __                 __
  / __ \ ____   ___   ____     / __ \ ___   / /____ _ __  __   / ____// /_   ___   _____ / /__
 / / / // __ \ / _ \ / __ \   / /_/ // _ \ / // __ `// / / /  / /    / __ \ / _ \ / ___// //_/
/ /_/ // /_/ //  __// / / /  / _, _//  __// // /_/ // /_/ /  / /___ / / / //  __// /__ / ,<
\____// .___/ \___//_/ /_/  /_/ |_| \___//_/ \__,_/ \__, /   \____//_/ /_/ \___/ \___//_/|_|
     /_/                                           /____/
         SMTP Open-Relay Spoofing Tester -- for AUTHORIZED security testing only

Beware! Publicly reachable mail servers configured as an OPEN RELAY can be
abused to send spoofed email. Only test servers you own or are authorized
to assess.
"""


def prompt(text, required=True):
    while True:
        try:
            value = input(text).strip()
        except KeyboardInterrupt:
            print("\n[!] Process interrupted by user.")
            sys.exit(1)
        except EOFError:
            print("\n[!] No input received.")
            sys.exit(1)
        if value or not required:
            return value
        print("[!] This field is required.")


def split_addresses(raw):
    """Split a comma-separated address list and drop empties/whitespace."""
    return [addr.strip() for addr in raw.split(',') if addr.strip()]


def looks_like_email(addr):
    # Deliberately permissive (this tool must accept spoofed/arbitrary
    # From addresses) -- just enough to catch obvious typos/empty input.
    return '@' in addr and not addr.startswith('@') and not addr.endswith('@')


def read_body_interactively():
    print("\nEnter the message body. Press Ctrl+D (Unix) or Ctrl+Z then Enter "
          "(Windows) to finish:\n")
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    return '\n'.join(lines)


def build_message(fromaddr, toaddrs, ccaddrs, subject, body):
    msg = EmailMessage()
    msg['From'] = fromaddr
    msg['To'] = ', '.join(toaddrs)
    if ccaddrs:
        msg['Cc'] = ', '.join(ccaddrs)
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    msg.set_content(body)
    return msg


def send_message(args, msg, fromaddr, all_rcpts):
    timeout = args.timeout
    try:
        if args.ssl:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(args.server, args.port, timeout=timeout,
                                       context=context)
        else:
            server = smtplib.SMTP(args.server, args.port, timeout=timeout)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as exc:
        print(f"[!] Could not connect to {args.server}:{args.port} -- {exc}")
        return False

    with server:
        try:
            server.set_debuglevel(1 if args.verbose else 0)
            server.ehlo()

            if not args.ssl and args.starttls:
                if server.has_extn('STARTTLS'):
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                else:
                    print("[!] Server does not advertise STARTTLS; "
                          "continuing without it.")

            if args.username:
                password = args.password
                if password is None:
                    import getpass
                    password = getpass.getpass(f"Password for {args.username}: ")
                try:
                    server.login(args.username, password)
                except smtplib.SMTPAuthenticationError as exc:
                    print(f"[!] Authentication failed: {exc}")
                    return False

            refused = server.sendmail(fromaddr, all_rcpts, msg.as_string())

            if refused:
                print("[!] Server accepted the connection but refused some "
                      "recipients (not an open relay for these):")
                for addr, (code, resp) in refused.items():
                    print(f"    - {addr}: {code} {resp.decode(errors='replace') if isinstance(resp, bytes) else resp}")
                if len(refused) == len(all_rcpts):
                    return False
                return True

            print(f"[+] Message accepted by {args.server}:{args.port} for all "
                  f"{len(all_rcpts)} recipient(s). This indicates the server "
                  f"relayed/accepted mail from an unauthenticated/spoofed "
                  f"sender -- flag it as an OPEN RELAY finding if unauthorized "
                  f"relaying was not expected.")
            return True

        except smtplib.SMTPRecipientsRefused as exc:
            print(f"[!] All recipients refused: {exc.recipients}")
            return False
        except smtplib.SMTPSenderRefused as exc:
            print(f"[!] Sender address refused by server: {exc}")
            return False
        except smtplib.SMTPHeloError as exc:
            print(f"[!] Server refused HELO/EHLO: {exc}")
            return False
        except smtplib.SMTPException as exc:
            print(f"[!] SMTP error: {exc}")
            return False
        except (socket.timeout, ConnectionResetError, OSError) as exc:
            print(f"[!] Connection error while sending: {exc}")
            return False


def parse_args():
    p = argparse.ArgumentParser(
        description="SMTP open-relay spoofing tester for authorized security testing.")
    p.add_argument('--server', help="SMTP server host/IP")
    p.add_argument('--port', type=int, default=25, help="SMTP port (default: 25)")
    p.add_argument('--from', dest='fromaddr', help="Envelope/From address (can be arbitrary)")
    p.add_argument('--to', help="Comma-separated recipient address(es)")
    p.add_argument('--cc', default='', help="Comma-separated Cc address(es)")
    p.add_argument('--subject', default='', help="Email subject")
    p.add_argument('--body', help="Email body text (if omitted, read from stdin/prompt)")
    p.add_argument('--starttls', action='store_true', help="Use STARTTLS if offered")
    p.add_argument('--ssl', action='store_true', help="Connect using implicit TLS (SMTPS)")
    p.add_argument('--username', help="SMTP AUTH username (optional)")
    p.add_argument('--password', help="SMTP AUTH password (optional; prompted if username given and this is omitted)")
    p.add_argument('--timeout', type=float, default=15.0, help="Connection timeout in seconds (default: 15)")
    p.add_argument('--yes', action='store_true', help="Skip the confirmation prompt")
    p.add_argument('--verbose', action='store_true', help="Show raw SMTP protocol exchange")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    fromaddr = args.fromaddr or prompt("From address (e.g., attacker@example.com): ")
    if not looks_like_email(fromaddr):
        print("[!] That doesn't look like a valid email address.")
        sys.exit(2)

    to_raw = args.to if args.to is not None else prompt("To address(es), comma-separated: ")
    toaddrs = split_addresses(to_raw)
    if not toaddrs:
        print("[!] At least one recipient is required.")
        sys.exit(2)
    bad = [a for a in toaddrs if not looks_like_email(a)]
    if bad:
        print(f"[!] Invalid recipient address(es): {', '.join(bad)}")
        sys.exit(2)

    ccaddrs = split_addresses(args.cc) if args.cc else []

    server_address = args.server or prompt("Mail server (e.g., smtp.example.com): ")
    if not server_address:
        print("[!] A mail server is required.")
        sys.exit(2)

    subject = args.subject
    if subject == '' and args.body is None and args.fromaddr is None:
        # Fully interactive flow: ask for a subject too.
        subject = prompt("Subject (optional): ", required=False)

    body = args.body if args.body is not None else read_body_interactively()

    all_rcpts = toaddrs + ccaddrs
    msg = build_message(fromaddr, toaddrs, ccaddrs, subject, body)

    print(f"\n[+] Message ready ({len(msg.as_bytes())} bytes). "
          f"From={fromaddr} To={toaddrs} Cc={ccaddrs} Server={server_address}:{args.port}")

    if not args.yes:
        confirm = prompt("Proceed with sending? [y/N]: ", required=False)
        if confirm.lower() not in ('y', 'yes'):
            print("[!] Aborted by user.")
            sys.exit(0)

    ok = send_message(args, msg, fromaddr, all_rcpts)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
