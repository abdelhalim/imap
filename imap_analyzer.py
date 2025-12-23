#!/usr/bin/env python3
"""
IMAP Email Domain Analyzer

Connects to an IMAP server, fetches email headers efficiently,
and analyzes sender domains by counting emails per domain.
"""

import imaplib
import email
import email.header
import re
from collections import Counter
from typing import Dict, List, Tuple
import ssl
import sys


class IMAPAnalyzer:
    """Analyzes email domains from IMAP server."""
    
    def __init__(self, server: str, port: int = 993, use_ssl: bool = True):
        """
        Initialize IMAP analyzer.
        
        Args:
            server: IMAP server address
            port: IMAP server port (default 993 for SSL)
            use_ssl: Whether to use SSL/TLS (default True)
        """
        self.server = server
        self.port = port
        self.use_ssl = use_ssl
        self.imap = None
        self.batch_size = 1000  # Fetch headers in batches for efficiency
        
    def connect(self, username: str, password: str) -> bool:
        """
        Connect and authenticate to IMAP server.
        
        Args:
            username: Email username
            password: Email password or app-specific password
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self.use_ssl:
                # Create SSL context
                context = ssl.create_default_context()
                self.imap = imaplib.IMAP4_SSL(self.server, self.port, ssl_context=context)
            else:
                self.imap = imaplib.IMAP4(self.server, self.port)
            
            # Authenticate
            self.imap.login(username, password)
            print(f"✓ Connected to {self.server}:{self.port}")
            return True
        except imaplib.IMAP4.error as e:
            print(f"✗ Authentication failed: {e}")
            return False
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def select_mailbox(self, mailbox: str = "INBOX") -> bool:
        """
        Select mailbox to analyze (read-only mode).
        
        Args:
            mailbox: Mailbox name (default: "INBOX")
            
        Returns:
            True if selection successful, False otherwise
        """
        try:
            # Use select() with readonly=True for read-only access
            # This avoids "not writable" errors on some servers
            status, messages = self.imap.select(mailbox, readonly=True)
            if status == "OK":
                num_messages = int(messages[0])
                print(f"✓ Selected {mailbox}: {num_messages} emails found")
                return True
            else:
                print(f"✗ Failed to select mailbox: {status}")
                return False
        except Exception as e:
            print(f"✗ Error selecting mailbox: {e}")
            return False
    
    def decode_header(self, header_value: str) -> str:
        """
        Decode email header value (handles encoded words).
        
        Args:
            header_value: Raw header value
            
        Returns:
            Decoded header value
        """
        if not header_value:
            return ""
        
        try:
            decoded_parts = email.header.decode_header(header_value)
            decoded_string = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding)
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            return decoded_string
        except Exception:
            return str(header_value)
    
    def extract_domain(self, from_header: str) -> str:
        """
        Extract domain from email address in From header.
        
        Args:
            from_header: From header value (e.g., "Name <user@domain.com>" or "user@domain.com")
            
        Returns:
            Domain name or "unknown" if extraction fails
        """
        if not from_header:
            return "unknown"
        
        # Pattern to match email addresses
        email_pattern = r'[\w\.-]+@([\w\.-]+\.\w+)'
        
        # Find all email addresses in the header
        matches = re.findall(email_pattern, from_header, re.IGNORECASE)
        
        if matches:
            # Return the first domain found (most common case)
            return matches[0].lower()
        
        return "unknown"
    
    def extract_email(self, from_header: str) -> str:
        """
        Extract full email address from From header.
        
        Args:
            from_header: From header value (e.g., "Name <user@domain.com>" or "user@domain.com")
            
        Returns:
            Full email address or "unknown" if extraction fails
        """
        if not from_header:
            return "unknown"
        
        # Pattern to match full email addresses
        # Matches: user@domain.com or <user@domain.com>
        email_pattern = r'([\w\.-]+@[\w\.-]+\.\w+)'
        
        # Find all email addresses in the header
        matches = re.findall(email_pattern, from_header, re.IGNORECASE)
        
        if matches:
            # Return the first email found (most common case)
            return matches[0].lower()
        
        return "unknown"
    
    def fetch_headers_batch(self, start: int, end: int) -> List[Tuple[int, str]]:
        """
        Fetch headers for a batch of emails using a UID range.
        
        Args:
            start: Starting email UID/sequence number
            end: Ending email UID/sequence number
            
        Returns:
            List of tuples (email_num, from_header)
        """
        headers = []
        try:
            # Fetch only the From header for efficiency
            # Using UID FETCH for better reliability with large mailboxes
            status, messages = self.imap.uid('FETCH', f'{start}:{end}', '(BODY[HEADER.FIELDS (FROM)])')
            
            if status != "OK":
                return headers
            
            current_uid = None
            for response_part in messages:
                if isinstance(response_part, tuple):
                    # Parse the response
                    if len(response_part) == 2:
                        uid_data = response_part[0]
                        header_data = response_part[1]
                        
                        # Extract UID from response (format: b'1 (BODY[HEADER.FIELDS (FROM)] {123}') or similar
                        if isinstance(uid_data, bytes):
                            uid_str = uid_data.decode('utf-8', errors='ignore')
                        else:
                            uid_str = str(uid_data)
                        
                        # Extract UID number (first number in the string)
                        uid_match = re.search(r'\b(\d+)\b', uid_str)
                        if uid_match:
                            current_uid = int(uid_match.group(1))
                        
                        # Parse header
                        if header_data:
                            try:
                                if isinstance(header_data, bytes):
                                    msg = email.message_from_bytes(header_data)
                                else:
                                    msg = email.message_from_string(str(header_data))
                                
                                from_header = msg.get('From', '')
                                if from_header:
                                    decoded_from = self.decode_header(from_header)
                                    headers.append((current_uid, decoded_from))
                            except Exception:
                                # Skip malformed headers
                                continue
            
            return headers
        except Exception as e:
            print(f"Warning: Error fetching batch {start}-{end}: {e}")
            return headers
    
    def fetch_headers_batch_by_uids(self, uids: List[int]) -> List[Tuple[int, str]]:
        """
        Fetch headers for specific UIDs (not a range).
        This ensures we only fetch the exact emails from our search results.
        
        Args:
            uids: List of specific UIDs to fetch
            
        Returns:
            List of tuples (email_num, from_header)
        """
        if not uids:
            return []
        
        headers = []
        try:
            # Build UID list string (e.g., "100,150,200")
            uid_list = ','.join(str(uid) for uid in uids)
            
            # Fetch only the From header for efficiency
            status, messages = self.imap.uid('FETCH', uid_list, '(BODY[HEADER.FIELDS (FROM)])')
            
            if status != "OK":
                return headers
            
            current_uid = None
            for response_part in messages:
                if isinstance(response_part, tuple):
                    # Parse the response
                    if len(response_part) == 2:
                        uid_data = response_part[0]
                        header_data = response_part[1]
                        
                        # Extract UID from response
                        if isinstance(uid_data, bytes):
                            uid_str = uid_data.decode('utf-8', errors='ignore')
                        else:
                            uid_str = str(uid_data)
                        
                        # Extract UID number (first number in the string)
                        uid_match = re.search(r'\b(\d+)\b', uid_str)
                        if uid_match:
                            current_uid = int(uid_match.group(1))
                        
                        # Parse header
                        if header_data:
                            try:
                                if isinstance(header_data, bytes):
                                    msg = email.message_from_bytes(header_data)
                                else:
                                    msg = email.message_from_string(str(header_data))
                                
                                from_header = msg.get('From', '')
                                if from_header:
                                    decoded_from = self.decode_header(from_header)
                                    headers.append((current_uid, decoded_from))
                            except Exception:
                                # Skip malformed headers
                                continue
            
            return headers
        except Exception as e:
            print(f"Warning: Error fetching batch for UIDs {uids[:5]}...: {e}")
            return headers
    
    def get_all_uids(self, unread_only: bool = True) -> List[int]:
        """
        Get email UIDs in the selected mailbox.
        
        Args:
            unread_only: If True, only return unread emails. If False, return all emails.
        
        Returns:
            List of email UIDs
        """
        try:
            if unread_only:
                # Search for unread emails only
                # Try UNSEEN first (standard IMAP), fallback to NOT SEEN if needed
                # UNSEEN means messages that do not have the \Seen flag set
                try:
                    status, messages = self.imap.uid('SEARCH', None, 'UNSEEN')
                    # If UNSEEN doesn't work, try alternative: NOT SEEN
                    if status != "OK":
                        status, messages = self.imap.uid('SEARCH', None, 'NOT', 'SEEN')
                except Exception:
                    # Fallback to NOT SEEN syntax
                    status, messages = self.imap.uid('SEARCH', None, 'NOT', 'SEEN')
            else:
                # Search for all emails
                status, messages = self.imap.uid('SEARCH', None, 'ALL')
            
            if status != "OK":
                print(f"Warning: Search returned status: {status}")
                return []
            
            if not messages or not messages[0]:
                return []
            
            # Parse UIDs from response
            uid_string = messages[0].decode('utf-8') if isinstance(messages[0], bytes) else str(messages[0])
            if not uid_string.strip():
                return []
            
            uids = [int(uid) for uid in uid_string.split() if uid.strip().isdigit()]
            return sorted(uids)
        except Exception as e:
            print(f"Error getting UIDs: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def analyze_domains(self, mailbox: str = "INBOX", unread_only: bool = True, group_by_email: bool = False) -> Dict[str, int]:
        """
        Analyze email domains or sender emails from selected mailbox.
        
        Args:
            mailbox: Mailbox name to analyze
            unread_only: If True, only analyze unread emails. If False, analyze all emails.
            group_by_email: If True, group by full sender email. If False, group by domain.
            
        Returns:
            Dictionary mapping domain names or email addresses to email counts
        """
        if not self.imap:
            print("✗ Not connected to IMAP server")
            return {}
        
        # Select mailbox
        if not self.select_mailbox(mailbox):
            return {}
        
        # Get email UIDs (unread only or all)
        filter_type = "unread" if unread_only else "all"
        grouping_type = "email addresses" if group_by_email else "domains"
        print(f"Fetching {filter_type} email UIDs (grouping by {grouping_type})...")
        uids = self.get_all_uids(unread_only=unread_only)
        total_emails = len(uids)
        
        if total_emails == 0:
            filter_msg = "unread " if unread_only else ""
            print(f"No {filter_msg}emails found in mailbox")
            return {}
        
        # If filtering for unread, verify a sample to ensure search is working
        if unread_only and total_emails > 0:
            # Verify first few UIDs are actually unread by checking flags
            sample_size = min(5, total_emails)
            verified_unread = 0
            try:
                for uid in uids[:sample_size]:
                    status, flags = self.imap.uid('FETCH', str(uid), '(FLAGS)')
                    if status == "OK" and flags:
                        # Check if \Seen flag is NOT present (meaning unread)
                        flags_str = str(flags[0]) if flags else ""
                        if r'\Seen' not in flags_str:
                            verified_unread += 1
                if verified_unread < sample_size:
                    print(f"Warning: Only {verified_unread}/{sample_size} sampled emails are actually unread.")
                    print("This may indicate the UNSEEN search is not working correctly with this server.")
            except Exception as e:
                print(f"Warning: Could not verify unread status: {e}")
        
        print(f"Processing {total_emails} {filter_type} emails in batches of {self.batch_size}...")
        
        domain_counter = Counter()
        processed = 0
        successfully_processed = 0
        
        # Process emails in batches
        for i in range(0, len(uids), self.batch_size):
            batch_uids = uids[i:i + self.batch_size]
            
            # Fetch headers for this batch using specific UIDs (not a range)
            # This ensures we only fetch the emails from our search results
            headers = self.fetch_headers_batch_by_uids(batch_uids)
            
            # Extract domains or emails based on grouping preference
            for uid, from_header in headers:
                if group_by_email:
                    key = self.extract_email(from_header)
                else:
                    key = self.extract_domain(from_header)
                domain_counter[key] += 1
                successfully_processed += 1
            
            processed += len(batch_uids)
            progress = (processed / total_emails) * 100
            print(f"Progress: {processed}/{total_emails} ({progress:.1f}%)", end='\r')
        
        print(f"\n✓ Processed {processed} emails ({successfully_processed} with valid headers)")
        return dict(domain_counter)
    
    def print_results(self, domain_counts: Dict[str, int], group_by_email: bool = False):
        """
        Print sorted domain or email analysis results.
        
        Args:
            domain_counts: Dictionary mapping domains/emails to email counts
            group_by_email: If True, label as "Email", otherwise "Domain"
        """
        if not domain_counts:
            label = "emails" if group_by_email else "domains"
            print(f"No {label} found")
            return
        
        # Sort by count (descending)
        sorted_items = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        
        label = "Email" if group_by_email else "Domain"
        print("\n" + "=" * 70)
        print(f"{label:<50} {'Count':>10} {'Percentage':>10}")
        print("=" * 70)
        
        total_emails = sum(domain_counts.values())
        
        for item, count in sorted_items:
            percentage = (count / total_emails) * 100
            print(f"{item:<50} {count:>10} {percentage:>9.2f}%")
        
        print("=" * 70)
        print(f"{'Total':<50} {total_emails:>10} {'100.00%':>10}")
    
    def close(self):
        """Close IMAP connection."""
        if self.imap:
            try:
                self.imap.close()
                self.imap.logout()
                print("✓ Connection closed")
            except Exception:
                pass


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze email domains from IMAP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password
  python imap_analyzer.py -s imap.gmail.com -u user@gmail.com -p password -m "Sent"
  python imap_analyzer.py -s mail.example.com -u user@example.com -p pass --port 143 --no-ssl
        """
    )
    
    parser.add_argument('-s', '--server', required=True, help='IMAP server address')
    parser.add_argument('-u', '--username', required=True, help='Email username')
    parser.add_argument('-p', '--password', required=True, help='Email password')
    parser.add_argument('-m', '--mailbox', default='INBOX', help='Mailbox to analyze (default: INBOX)')
    parser.add_argument('--port', type=int, default=993, help='IMAP port (default: 993)')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL/TLS')
    parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for fetching (default: 1000)')
    parser.add_argument('--all', action='store_true', help='Process all emails (default: unread emails only)')
    parser.add_argument('--group-by-email', action='store_true', help='Group by sender email address (default: group by domain)')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = IMAPAnalyzer(
        server=args.server,
        port=args.port,
        use_ssl=not args.no_ssl
    )
    analyzer.batch_size = args.batch_size
    
    try:
        # Connect and authenticate
        if not analyzer.connect(args.username, args.password):
            sys.exit(1)
        
        # Analyze domains or emails (default: unread only, unless --all is specified)
        # Note: group_by_email only affects how results are grouped, not which emails are fetched
        unread_only = not args.all  # True by default (unread only), False if --all is passed
        domain_counts = analyzer.analyze_domains(
            args.mailbox, 
            unread_only=unread_only,
            group_by_email=args.group_by_email
        )
        
        # Print results
        analyzer.print_results(domain_counts, group_by_email=args.group_by_email)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()

