# IMAP Email Domain Analyzer

A fast Python script that connects to an IMAP server, fetches email headers efficiently, and analyzes sender domains by counting emails per domain.

## Features

- **Fast bulk fetching**: Processes emails in configurable batches (default: 1000) for optimal performance
- **Efficient header parsing**: Only fetches the `From` header field to minimize data transfer
- **Unread email filtering**: By default, processes only unread emails (use `--all` for all emails)
- **Flexible grouping**: Group by sender domain (default) or by full sender email address
- **Domain/Email extraction**: Automatically extracts sender domains or full email addresses
- **Sorted statistics**: Displays results sorted by email count with percentages

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Usage

### Basic Usage

```bash
python imap_analyzer.py -s imap.gmail.com -u your.email@gmail.com -p your_password
```

### Command Line Arguments

- `-s, --server`: IMAP server address (required)
- `-u, --username`: Email username (required)
- `-p, --password`: Email password or app-specific password (required)
- `-m, --mailbox`: Mailbox to analyze (default: `INBOX`)
- `--port`: IMAP port (default: `993` for SSL)
- `--no-ssl`: Disable SSL/TLS (use for port 143)
- `--batch-size`: Number of emails to fetch per batch (default: `1000`)
- `--all`: Process all emails (default: unread emails only)
- `--group-by-email`: Group by sender email address instead of domain (default: group by domain)

### Examples

**Analyze Gmail inbox:**
```bash
python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p app_password
```

**Analyze a different mailbox:**
```bash
python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password -m "Sent"
```

**Use non-SSL connection (port 143):**
```bash
python imap_analyzer.py -s mail.example.com -u user@example.com -p password --port 143 --no-ssl
```

**Custom batch size for very large mailboxes:**
```bash
python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password --batch-size 2000
```

**Process all emails (not just unread):**
```bash
python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password --all
```

**Group by sender email address instead of domain:**
```bash
python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password --group-by-email
```

## Gmail Setup

For Gmail, you'll need to:
1. Enable 2-factor authentication
2. Generate an app-specific password: https://myaccount.google.com/apppasswords
3. Use the app-specific password instead of your regular password

## Output Format

The script displays a sorted table showing:
- Domain name or email address (depending on grouping mode)
- Email count
- Percentage of total emails

**Example output (grouped by domain):**
```
======================================================================
Domain                                          Count  Percentage
======================================================================
gmail.com                                           1250     12.50%
example.com                                          850      8.50%
...
======================================================================
Total                                              10000    100.00%
```

**Example output (grouped by email with `--group-by-email`):**
```
======================================================================
Email                                             Count  Percentage
======================================================================
sender1@example.com                                  450      4.50%
sender2@example.com                                  320      3.20%
...
======================================================================
Total                                              10000    100.00%
```

## Performance

The script is optimized for large mailboxes:
- Uses UID-based fetching for reliability
- Fetches only necessary header fields
- Processes emails in batches to minimize memory usage
- Shows progress during processing

For mailboxes with 10,000+ emails, expect processing times of a few minutes depending on network speed and server response time.

