import email
import re
import sys
from email import policy
from email.parser import BytesParser

def analyze_email(file_path):
    print("\n===== PHISHING EMAIL ANALYZER =====\n")

    # Open and parse the .eml file
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # --- BASIC INFO ---
    print("📧 BASIC INFO")
    print(f"  From:     {msg['from']}")
    print(f"  Reply-To: {msg['reply-to']}")
    print(f"  To:       {msg['to']}")
    print(f"  Subject:  {msg['subject']}")
    print(f"  Date:     {msg['date']}")

    # --- SUSPICIOUS CHECKS ---
    print("\n🚨 SUSPICIOUS CHECKS")
    flags = []

    # Check if From and Reply-To are different
    sender = str(msg['from'])
    reply_to = str(msg['reply-to'])
    if msg['reply-to'] and reply_to not in sender:
        flags.append("⚠️  Reply-To differs from From address (possible spoofing)")

    # Check for urgency words in subject
    subject = str(msg['subject']).lower()
    urgency_words = ['urgent', 'immediate', 'verify', 'suspended', 'unusual', 'confirm', 'action required']
    found_urgency = [w for w in urgency_words if w in subject]
    if found_urgency:
        flags.append(f"⚠️  Urgency words in subject: {found_urgency}")

    # --- EXTRACT LINKS ---
    print("\n🔗 LINKS FOUND IN EMAIL")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    urls = re.findall(r'https?://[^\s<>"]+', body)
    if urls:
        for url in urls:
            print(f"  - {url}")
        # Flag shortened URLs
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
        for url in urls:
            if any(s in url for s in shorteners):
                flags.append(f"⚠️  Shortened URL detected: {url}")
    else:
        print("  No links found.")

    # --- ATTACHMENTS ---
    print("\n📎 ATTACHMENTS")
    dangerous_extensions = ['.exe', '.zip', '.js', '.vbs', '.bat', '.docm', '.xlsm']
    found_attachments = False
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            found_attachments = True
            print(f"  - {filename}")
            if any(filename.endswith(ext) for ext in dangerous_extensions):
                flags.append(f"⚠️  Dangerous attachment: {filename}")
    if not found_attachments:
        print("  No attachments found.")

    # --- SUMMARY ---
    print("\n📋 SUMMARY")
    if flags:
        print("  🔴 Suspicious indicators found:")
        for flag in flags:
            print(f"    {flag}")
    else:
        print("  ✅ No obvious phishing indicators detected.")

    print("\n===================================\n")

# Run it
if len(sys.argv) < 2:
    print("Usage: python analyzer.py youremail.eml")
else:
    analyze_email(sys.argv[1])