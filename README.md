# Phishing Email Analyzer

A Python command-line tool that analyzes .eml email files for common phishing indicators and checks links against VirusTotal. Built to mirror the first steps of a SOC phishing triage.

## Features
- Extracts email headers (From, Reply-To, To, Subject, Date)
- Detects a Reply-To address that differs from the sender (possible spoofing)
- Flags urgency language in the subject line
- Extracts URLs from the email body and flags link shorteners
- Checks up to 4 URLs per email against the VirusTotal API
- Lists attachments and flags risky file types (.exe, .zip, .js, .vbs, .bat, .docm, .xlsm)
- Prints a summary of every red flag found

## Setup
1. Install Python 3 and the requests library:
```bash
pip3 install requests
```
2. Get a free API key from virustotal.com (profile icon > API Key).
3. Set the key as an environment variable. Do not put it in the code:
```bash
export VT_API_KEY="your_key_here"
```

## Usage
```bash
python3 analyzer.py email.eml
```
A sample phishing email is included as test.eml.

Without VT_API_KEY set, the tool still runs all the other checks and skips the VirusTotal lookups.

## Example Output
```
Suspicious indicators found:
  Reply-To differs from From address (possible spoofing)
  Urgency words in subject: ['urgent', 'verify']
  Shortened URL detected: https://bit.ly/abc123
  VirusTotal flagged URL: https://bit.ly/abc123
```

## MITRE ATT&CK
Covers the detection side of T1566 (Phishing), including T1566.001 (Spearphishing Attachment) and T1566.002 (Spearphishing Link).

## Limitations
- Only reads the plain-text part of an email, so links that appear only in HTML bodies are not found yet
- The free VirusTotal plan allows 4 requests per minute, so lookups are limited to 4 URLs with a 15 second delay between them
- Keyword and extension checks are simple heuristics and will not catch everything

## Planned Improvements
- Parse HTML email bodies
- Check sender domain against SPF, DKIM, and DMARC results in the headers
- Export the triage report to a file

## Built by
Umar Khan, SOC Analyst Intern
