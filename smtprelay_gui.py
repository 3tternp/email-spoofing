#!/usr/bin/env python3
"""
SMTP Open-Relay Spoofing Tester (GUI)
======================================

A Tkinter-based graphical front end for checking whether a mail server is
mis-configured as an open relay (will accept/relay mail with an arbitrary,
unauthenticated sender address).

Legal / ethical notice
-----------------------
Only run this against mail infrastructure you own or are explicitly
authorized to test (e.g. an approved penetration test or CTF). Sending
spoofed mail to third parties without authorization is abuse and, in many
jurisdictions, illegal. This tool requires you to tick an authorization
checkbox before it will send anything.

Dependencies: Python 3 standard library only (tkinter, smtplib, email).
Run with:  python3 smtprelay_gui.py
"""

import smtplib
import socket
import ssl
import sys
import threading
import tkinter as tk
from datetime import datetime
from email.message import EmailMessage
from email.utils import make_msgid, formatdate
from tkinter import ttk, messagebox, scrolledtext

APP_TITLE = "SMTP Open-Relay Spoofing Tester"


def split_addresses(raw):
    return [a.strip() for a in raw.split(',') if a.strip()]


def looks_like_email(addr):
    return bool(addr) and '@' in addr and not addr.startswith('@') and not addr.endswith('@')


class SmtpRelayGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        self.master = master
        self.master.title(APP_TITLE)
        self.master.geometry("760x680")
        self.master.minsize(620, 560)

        self._build_warning_banner()
        self._build_connection_section()
        self._build_message_section()
        self._build_actions_section()
        self._build_log_section()

        self.pack(fill=tk.BOTH, expand=True)
        self.send_thread = None

    # ---------------------------------------------------------------- UI ---

    def _build_warning_banner(self):
        banner = ttk.Label(
            self,
            text=("⚠  Authorized security testing only. Only test mail servers you own "
                  "or have explicit written permission to assess. Spoofing mail to real "
                  "third parties without authorization is abuse and may be illegal."),
            wraplength=720, justify=tk.LEFT, foreground="#b00020",
            font=("TkDefaultFont", 9, "bold"),
        )
        banner.pack(fill=tk.X, pady=(0, 10))

    def _build_connection_section(self):
        frame = ttk.LabelFrame(self, text="Target SMTP server", padding=10)
        frame.pack(fill=tk.X, pady=(0, 10))

        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=0)

        ttk.Label(frame, text="Server host/IP:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.server_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.server_var).grid(
            row=0, column=1, sticky=tk.EW, padx=(6, 12), pady=3)

        ttk.Label(frame, text="Port:").grid(row=0, column=2, sticky=tk.W, pady=3)
        self.port_var = tk.StringVar(value="25")
        ttk.Entry(frame, textvariable=self.port_var, width=8).grid(
            row=0, column=3, sticky=tk.W, pady=3)

        self.security_var = tk.StringVar(value="none")
        sec_frame = ttk.Frame(frame)
        sec_frame.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(4, 3))
        ttk.Label(sec_frame, text="Security:").pack(side=tk.LEFT)
        for label, value in (("None (plain)", "none"), ("STARTTLS", "starttls"), ("Implicit TLS/SSL", "ssl")):
            ttk.Radiobutton(sec_frame, text=label, value=value, variable=self.security_var).pack(
                side=tk.LEFT, padx=(10, 0))

        ttk.Label(frame, text="AUTH username (optional):").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var).grid(
            row=2, column=1, sticky=tk.EW, padx=(6, 12), pady=3)

        ttk.Label(frame, text="AUTH password:").grid(row=2, column=2, sticky=tk.W, pady=3)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*").grid(
            row=2, column=3, sticky=tk.EW, pady=3)

        ttk.Label(frame, text="Timeout (s):").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.timeout_var = tk.StringVar(value="15")
        ttk.Entry(frame, textvariable=self.timeout_var, width=8).grid(
            row=3, column=1, sticky=tk.W, pady=3)

    def _build_message_section(self):
        frame = ttk.LabelFrame(self, text="Message", padding=10)
        frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="From (spoofed sender):").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.from_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.from_var).grid(row=0, column=1, sticky=tk.EW, padx=(6, 0), pady=3)

        ttk.Label(frame, text="To (comma-separated):").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.to_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.to_var).grid(row=1, column=1, sticky=tk.EW, padx=(6, 0), pady=3)

        ttk.Label(frame, text="Cc (optional):").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.cc_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.cc_var).grid(row=2, column=1, sticky=tk.EW, padx=(6, 0), pady=3)

        ttk.Label(frame, text="Subject:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.subject_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.subject_var).grid(row=3, column=1, sticky=tk.EW, padx=(6, 0), pady=3)

        ttk.Label(frame, text="Body:").grid(row=4, column=0, sticky=tk.NW, pady=3)
        self.body_text = tk.Text(frame, height=8, wrap=tk.WORD)
        self.body_text.grid(row=4, column=1, sticky=tk.NSEW, padx=(6, 0), pady=3)
        frame.rowconfigure(4, weight=1)

    def _build_actions_section(self):
        frame = ttk.Frame(self)
        frame.pack(fill=tk.X, pady=(0, 10))

        self.authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame,
            text="I am authorized to test this mail server for open-relay/spoofing vulnerabilities.",
            variable=self.authorized_var,
        ).pack(side=tk.LEFT)

        self.send_button = ttk.Button(frame, text="Send Test Email", command=self.on_send)
        self.send_button.pack(side=tk.RIGHT)

        self.clear_button = ttk.Button(frame, text="Clear Log", command=self.clear_log)
        self.clear_button.pack(side=tk.RIGHT, padx=(0, 8))

    def _build_log_section(self):
        frame = ttk.LabelFrame(self, text="Result / log", padding=6)
        frame.pack(fill=tk.BOTH, expand=True)
        self.log_widget = scrolledtext.ScrolledText(frame, height=10, state="disabled", wrap=tk.WORD)
        self.log_widget.pack(fill=tk.BOTH, expand=True)

    # ----------------------------------------------------------- helpers ---

    def log(self, message):
        def append():
            self.log_widget.configure(state="normal")
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_widget.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_widget.see(tk.END)
            self.log_widget.configure(state="disabled")
        self.master.after(0, append)

    def clear_log(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", tk.END)
        self.log_widget.configure(state="disabled")

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.send_button.configure(state=state)

    # ------------------------------------------------------------ actions ---

    def validate_inputs(self):
        server = self.server_var.get().strip()
        if not server:
            messagebox.showerror(APP_TITLE, "Server host/IP is required.")
            return None

        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror(APP_TITLE, "Port must be a number.")
            return None

        try:
            timeout = float(self.timeout_var.get().strip())
        except ValueError:
            messagebox.showerror(APP_TITLE, "Timeout must be a number.")
            return None

        fromaddr = self.from_var.get().strip()
        if not looks_like_email(fromaddr):
            messagebox.showerror(APP_TITLE, "Enter a valid From address.")
            return None

        toaddrs = split_addresses(self.to_var.get())
        if not toaddrs or any(not looks_like_email(a) for a in toaddrs):
            messagebox.showerror(APP_TITLE, "Enter at least one valid To address.")
            return None

        ccaddrs = split_addresses(self.cc_var.get())
        if any(not looks_like_email(a) for a in ccaddrs):
            messagebox.showerror(APP_TITLE, "Cc contains an invalid address.")
            return None

        if not self.authorized_var.get():
            messagebox.showwarning(
                APP_TITLE,
                "You must confirm you are authorized to test this server before sending.")
            return None

        return {
            "server": server,
            "port": port,
            "timeout": timeout,
            "security": self.security_var.get(),
            "username": self.username_var.get().strip(),
            "password": self.password_var.get(),
            "fromaddr": fromaddr,
            "toaddrs": toaddrs,
            "ccaddrs": ccaddrs,
            "subject": self.subject_var.get().strip(),
            "body": self.body_text.get("1.0", tk.END).rstrip("\n"),
        }

    def on_send(self):
        if self.send_thread and self.send_thread.is_alive():
            return
        params = self.validate_inputs()
        if params is None:
            return

        confirm = messagebox.askyesno(
            APP_TITLE,
            f"Send a test message to {len(params['toaddrs']) + len(params['ccaddrs'])} "
            f"recipient(s) via {params['server']}:{params['port']} using the From address "
            f"\"{params['fromaddr']}\"?\n\nProceed only if you are authorized to do so.")
        if not confirm:
            return

        self.set_busy(True)
        self.log(f"Connecting to {params['server']}:{params['port']} "
                  f"(security={params['security']})...")
        self.send_thread = threading.Thread(target=self._send_worker, args=(params,), daemon=True)
        self.send_thread.start()

    def _send_worker(self, params):
        try:
            ok = self._send_message(params)
        except Exception as exc:  # last-resort guard so the UI never hangs/crashes
            self.log(f"[!] Unexpected error: {exc}")
            ok = False
        finally:
            self.master.after(0, lambda: self.set_busy(False))
        if ok:
            self.master.after(0, lambda: messagebox.showinfo(
                APP_TITLE, "Message accepted by the server. See the log for details."))
        else:
            self.master.after(0, lambda: messagebox.showerror(
                APP_TITLE, "Sending failed or was refused. See the log for details."))

    def _build_message(self, params):
        msg = EmailMessage()
        msg['From'] = params['fromaddr']
        msg['To'] = ', '.join(params['toaddrs'])
        if params['ccaddrs']:
            msg['Cc'] = ', '.join(params['ccaddrs'])
        msg['Subject'] = params['subject']
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid()
        msg.set_content(params['body'])
        return msg

    def _send_message(self, params):
        all_rcpts = params['toaddrs'] + params['ccaddrs']
        msg = self._build_message(params)

        try:
            if params['security'] == 'ssl':
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(params['server'], params['port'],
                                           timeout=params['timeout'], context=context)
            else:
                server = smtplib.SMTP(params['server'], params['port'],
                                       timeout=params['timeout'])
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as exc:
            self.log(f"[!] Could not connect: {exc}")
            return False

        with server:
            try:
                server.ehlo()

                if params['security'] == 'starttls':
                    if server.has_extn('STARTTLS'):
                        server.starttls(context=ssl.create_default_context())
                        server.ehlo()
                    else:
                        self.log("[!] Server does not advertise STARTTLS; continuing without it.")

                if params['username']:
                    try:
                        server.login(params['username'], params['password'])
                        self.log(f"[+] Authenticated as {params['username']}.")
                    except smtplib.SMTPAuthenticationError as exc:
                        self.log(f"[!] Authentication failed: {exc}")
                        return False

                refused = server.sendmail(params['fromaddr'], all_rcpts, msg.as_string())

                if refused:
                    self.log("[!] Server refused some recipients (not an open relay for these):")
                    for addr, (code, resp) in refused.items():
                        resp_text = resp.decode(errors='replace') if isinstance(resp, bytes) else resp
                        self.log(f"    - {addr}: {code} {resp_text}")
                    if len(refused) == len(all_rcpts):
                        return False
                    return True

                self.log(f"[+] Message accepted by {params['server']}:{params['port']} for "
                         f"all {len(all_rcpts)} recipient(s). This indicates the server "
                         f"relayed/accepted mail from an unauthenticated/spoofed sender -- "
                         f"flag it as an OPEN RELAY finding if that was not expected.")
                return True

            except smtplib.SMTPRecipientsRefused as exc:
                self.log(f"[!] All recipients refused: {exc.recipients}")
                return False
            except smtplib.SMTPSenderRefused as exc:
                self.log(f"[!] Sender address refused by server: {exc}")
                return False
            except smtplib.SMTPHeloError as exc:
                self.log(f"[!] Server refused HELO/EHLO: {exc}")
                return False
            except smtplib.SMTPException as exc:
                self.log(f"[!] SMTP error: {exc}")
                return False
            except (socket.timeout, ConnectionResetError, OSError) as exc:
                self.log(f"[!] Connection error while sending: {exc}")
                return False


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"[!] Could not start the GUI (no display available?): {exc}")
        print("    Use smtprelay.py for a command-line / headless alternative.")
        sys.exit(1)

    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except tk.TclError:
        pass

    SmtpRelayGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
