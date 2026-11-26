<div align="center">

# 📧🕵️ Email Spoofing / SMTP Open‑Relay Tester

**Find out if a mail server will relay spoofed email — before an attacker does.**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/Interface-CLI-4D4D4D?logo=gnubash&logoColor=white)
![GUI](https://img.shields.io/badge/Interface-GUI%20(Tkinter)-2E8B57?logo=windowsterminal&logoColor=white)
![License](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-b00020)

</div>

---

## 📖 What is this?

This project checks whether a mail server is mis-configured as an **🔓 open
relay** — i.e. whether it will accept and deliver mail with an arbitrary,
unauthenticated `From` address. It is based on the original
[`emailspoofing`](https://github.com/balaganeshcyber/Emailspoofing) project
by GBHacker/Astra Cybersecurity.

📩 Email spoofing is the technique of delivering forged email to recipients.
Attackers abuse publicly reachable, mis-configured ("open relay") SMTP
servers to send spoofed mail for phishing, spam, or persistent
"legitimate-looking" backdoors.
📚 Reference: https://gbhackers.com/email-spoofing-exploiting-open-relay/

---

## 🚨 Authorized use only

> ⚠️ **Only point this tool at mail servers you own or are explicitly
> authorized to test** — an approved penetration test, red team engagement,
> or CTF. Sending spoofed email to real third-party recipients without
> authorization is abuse, can violate anti-spam/computer misuse laws, and is
> out of scope for this tool.
>
> ✅ The GUI requires you to tick an authorization checkbox before it will
> send anything.

---

## 🧰 What's included

| Icon | File | Description |
|:---:|---|---|
| ⌨️ | [`smtprelay.py`](smtprelay.py) | Command-line tool — interactive or fully scriptable via flags. |
| 🖥️ | [`smtprelay_gui.py`](smtprelay_gui.py) | Graphical (Tkinter) version with the same functionality. |

### ✨ Both tools

| | Capability |
|:---:|---|
| 📝 | Build a **proper RFC 5322 message** (correct `From`, `To`, `Cc`, `Subject`, `Date`, `Message-ID` headers) instead of a hand-built, header-incomplete string. |
| ✅ | **Validate** addresses and required fields before attempting to send. |
| 🔐 | Support **plaintext, STARTTLS, and implicit TLS/SSL** (SMTPS) connections. |
| 🔑 | Support optional **SMTP `AUTH LOGIN`** credentials — useful for testing relay rules that only apply to unauthenticated senders. |
| 🎯 | **Report real delivery outcome** — whether the server actually accepted the message for *all* recipients (a genuine open-relay finding) vs. refusing some/all of them — instead of assuming success just because `sendmail()` didn't raise. |
| ⏱️ | Use **connection timeouts** and give specific, actionable error messages (DNS failure, connection refused, auth failure, recipients refused) instead of swallowing every error as "an unexpected error occurred." |

---

## 📦 Requirements

- 🐍 Python 3.8+
- Standard library only:
  - ⌨️ CLI — `smtplib`, `email`, `ssl`, `socket`, `argparse`
  - 🖥️ GUI — `tkinter` (included with most Python installs; on
    Debian/Ubuntu run `sudo apt-get install python3-tk` if missing)

No third-party packages, no `pip install` required. 🎉

---

## 🖥️ Usage — GUI

```bash
python3 smtprelay_gui.py
```

1. 🌐 Enter the **target server** and pick a security mode — `None` /
   `STARTTLS` / `Implicit TLS`.
2. 🔑 Optionally fill in **AUTH credentials**.
3. ✉️ Fill in the spoofed **From**, **To**, **Cc**, **Subject**, and **Body**.
4. ☑️ Tick **"I am authorized to test this server"**.
5. 🚀 Click **Send Test Email**.

📊 Results (accepted / refused / connection errors) stream live into the log
pane at the bottom. Sending runs on a background thread, so the UI never
freezes. 🧵

<div align="center">

```
┌─────────────────────────────────────────────────────────┐
│ ⚠  Authorized security testing only                      │
├─────────────────────────────────────────────────────────┤
│ 🌐 Target SMTP server                                     │
│    Server host/IP   [________________]  Port [25]        │
│    Security:  ⦿ None   ○ STARTTLS   ○ Implicit TLS/SSL   │
│    AUTH user  [________]   AUTH password [••••••••]      │
├─────────────────────────────────────────────────────────┤
│ ✉️  Message                                                │
│    From  [attacker@example.com]                           │
│    To    [victim@example.com]                             │
│    Subject [Test]                                          │
│    Body  [..................................]             │
├─────────────────────────────────────────────────────────┤
│ ☑ I am authorized to test this mail server    [🚀 Send]   │
├─────────────────────────────────────────────────────────┤
│ 📜 Result / log                                            │
│ [+] Message accepted for all recipient(s)...               │
└─────────────────────────────────────────────────────────┘
```

</div>

---

## ⌨️ Usage — CLI

### 🗣️ Interactive mode

Same prompt flow as the original script, now with proper headers and validation:

```bash
python3 smtprelay.py
```

### 🤖 Non-interactive / scriptable mode

```bash
python3 smtprelay.py \
  --server smtp.example.com --port 25 \
  --from "attacker@example.com" \
  --to "victim@example.com" \
  --subject "Test" \
  --body "This is an authorized open-relay test." \
  --yes
```

### 🏷️ Useful flags

| Flag | Purpose |
|---|---|
| `--starttls` / `--ssl` | 🔐 Use STARTTLS or implicit TLS instead of plaintext. |
| `--username` / `--password` | 🔑 Authenticate before sending (password prompted securely if omitted). |
| `--cc` | 📋 Additional comma-separated Cc recipients. |
| `--timeout` | ⏱️ Connection timeout in seconds (default `15`). |
| `--verbose` | 🔍 Print the raw SMTP protocol exchange. |
| `--yes` | ⏩ Skip the confirmation prompt (for scripted/CI use in an authorized test). |

Run `python3 smtprelay.py --help` for the full list. 📚

---

## 📈 Interpreting results

| Outcome | Meaning |
|:---:|---|
| ✅ **Accepted for all recipients** | The server relayed/accepted mail from an unauthenticated or spoofed sender. Flag it as an **open-relay finding** if that behavior wasn't intended. |
| ⚠️ **Some/all recipients refused** | The server is enforcing relay restrictions for those addresses/domains — **not** an open-relay finding for that recipient. |
| ❌ **Connection/auth errors** | The server wasn't reachable on that port/security mode, or rejected the supplied credentials. |

---

<div align="center">

🛡️ *Built for defenders and authorized testers — use responsibly.* 🛡️

</div>
