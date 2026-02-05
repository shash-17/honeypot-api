"""Intelligence extraction from scam conversations - Robust version."""

import re
from typing import List, Dict
from models import ExtractedIntelligence
from groq import Groq


class IntelligenceExtractor:
    """Extracts actionable intelligence from scam messages with high accuracy."""

    def __init__(self, api_key: str = None):
        """Initialize extractor with optional Groq API key."""
        self.api_key = api_key
        if api_key:
            self.client = Groq(api_key=api_key)
            self.model = "llama-3.3-70b-versatile"
        else:
            self.client = None
            self.model = None

    def _normalize_text(self, text: str) -> str:
        """Normalize special characters in text."""
        # Replace various dash types with standard dash
        replacements = {
            '–': '-',  # en-dash
            '—': '-',  # em-dash
            '−': '-',  # minus sign
            ''': "'",  # curly quote
            ''': "'",
            '"': '"',
            '"': '"',
            '\u00a0': ' ',  # non-breaking space
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def _clean_extracted_value(self, value: str) -> str:
        """Clean trailing/leading punctuation from extracted values."""
        return value.strip().rstrip('.,;:!?)"\'>').lstrip('<"\'(')

    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract Indian bank account numbers (9-18 digits)."""
        text = self._normalize_text(text)
        accounts = set()
        
        # Pattern: 9-18 digit sequences (account numbers)
        for match in re.finditer(r'\b(\d{9,18})\b', text):
            num = match.group(1)
            # Filter out phone numbers (10-digit starting with 6-9)
            if len(num) == 10 and num[0] in '6789':
                continue
            # Filter out 91XXXXXXXXXX (phone with country code)
            if len(num) == 12 and num.startswith('91') and num[2] in '6789':
                continue
            accounts.add(num)
        
        # Pattern: Card format XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX
        for match in re.finditer(r'\b(\d{4})[-\s]?(\d{4})[-\s]?(\d{4})[-\s]?(\d{4})\b', text):
            accounts.add(''.join(match.groups()))
        
        return list(accounts)

    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs (format: something@bankhandle)."""
        text = self._normalize_text(text.lower())
        upi_ids = set()
        
        # Email TLDs to filter out
        email_tlds = {'.com', '.org', '.net', '.in', '.co', '.io', '.edu', 
                      '.gov', '.info', '.biz', '.me', '.us', '.uk', '.au'}
        
        # Common email providers to filter out  
        email_providers = {'gmail', 'yahoo', 'hotmail', 'outlook', 'email', 
                          'mail', 'protonmail', 'icloud', 'live', 'msn', 
                          'aol', 'rediffmail', 'zoho', 'yandex'}
        
        # Match word@word patterns
        for match in re.finditer(r'([a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9][a-zA-Z0-9._-]*)', text):
            upi = self._clean_extracted_value(match.group(1))
            
            if not upi or '@' not in upi:
                continue
                
            suffix = upi.split('@')[-1]
            
            # Skip if has email TLD
            if any(suffix.endswith(tld) for tld in email_tlds):
                continue
            
            # Skip if matches email provider
            if any(provider in suffix for provider in email_providers):
                continue
            
            upi_ids.add(upi)
        
        return list(upi_ids)

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers in various formats."""
        text = self._normalize_text(text)
        phones = set()
        
        # Pattern 1: +91 with 10 digits (various formats)
        for match in re.finditer(r'\+91[-\s.]?(\d{5})[-\s.]?(\d{5})', text):
            phones.add('+91' + match.group(1) + match.group(2))
        
        for match in re.finditer(r'\+91[-\s.]?(\d{10})\b', text):
            phones.add('+91' + match.group(1))
        
        # Pattern 2: 91 prefix (without +)
        for match in re.finditer(r'\b91[-\s.]?(\d{10})\b', text):
            phones.add('+91' + match.group(1))
        
        # Pattern 3: 0 prefix (landline format)
        for match in re.finditer(r'\b0(\d{10})\b', text):
            phones.add('+91' + match.group(1))
        
        # Pattern 4: Standalone 10-digit Indian mobile (starts with 6-9)
        for match in re.finditer(r'(?<!\d)([6-9]\d{9})(?!\d)', text):
            phones.add('+91' + match.group(1))
        
        return list(phones)

    def extract_phishing_links(self, text: str) -> List[str]:
        """Extract URLs and phishing links."""
        text = self._normalize_text(text)
        urls = set()
        
        # Pattern 1: Simple, aggressive regex for URLs
        # Matches http/https followed by non-whitespace characters
        print(f"DEBUG: Extracting URLs from text: {text[:50]}...")
        url_pattern = r'https?://[^\s<>"]+'
        for match in re.finditer(url_pattern, text, re.IGNORECASE):
            url = match.group(0)
            print(f"DEBUG: Regex matched: {url}")
            # Clean trailing punctuation
            url = url.rstrip('.,;:!?)">]')
            if url:
                urls.add(url)
                print(f"DEBUG: Added URL: {url}")
        
        # Pattern 2: www. URLs without protocol
        for match in re.finditer(r'\b(www\.[^\s<>"\'`\[\]{}|\\^]+)', text, re.IGNORECASE):
            url = self._clean_extracted_value(match.group(1))
            if url:
                urls.add('https://' + url)
        
        # Pattern 3: Common URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'cutt.ly', 
                      'shorturl.at', 'rb.gy', 'ow.ly', 'is.gd', 'v.gd']
        for shortener in shorteners:
            pattern = rf'({re.escape(shortener)}/[^\s<>"\']+)'
            for match in re.finditer(pattern, text, re.IGNORECASE):
                url = self._clean_extracted_value(match.group(1))
                if url:
                    urls.add('https://' + url if not url.startswith('http') else url)
        
        return list(urls)

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious/scam-related keywords."""
        keywords = [
            # Urgency
            "urgent", "immediately", "right now", "within minutes", "hurry",
            # Threats
            "blocked", "suspended", "freeze", "locked", "terminated", "deactivated",
            # Verification
            "verify", "confirm", "validate", "authenticate",
            # Credentials
            "otp", "pin", "password", "cvv", "mpin", "atm pin",
            # Identity
            "kyc", "pan", "aadhar", "identity", "pan card",
            # Money
            "refund", "cashback", "prize", "lottery", "winner", "reward", "bonus",
            # Actions
            "claim", "redeem", "collect", "receive",
            # Alerts
            "warning", "alert", "security", "unauthorized", "suspicious activity",
            # State
            "compromised", "hacked", "expired", "expiring"
        ]
        
        text_lower = text.lower()
        found = []
        
        for keyword in keywords:
            if keyword in text_lower:
                found.append(keyword)
        
        return list(set(found))

    def extract_all(self, messages: List[Dict]) -> ExtractedIntelligence:
        """Extract all intelligence from a list of messages."""
        # Combine all message text
        all_text = " ".join([str(msg.get("text", "")) for msg in messages])
        
        return ExtractedIntelligence(
            bankAccounts=self.extract_bank_accounts(all_text),
            upiIds=self.extract_upi_ids(all_text),
            phoneNumbers=self.extract_phone_numbers(all_text),
            phishingLinks=self.extract_phishing_links(all_text),
            suspiciousKeywords=self.extract_suspicious_keywords(all_text)
        )

    async def generate_agent_notes(self, messages: List[Dict], intelligence: ExtractedIntelligence = None) -> str:
        """Generate factual summary notes about the scam conversation."""
        # Extract intelligence if not provided
        if intelligence is None:
            intelligence = self.extract_all(messages)
        
        notes_parts = []
        keywords = intelligence.suspiciousKeywords
        
        # Determine scam type based on keywords
        if any(k in keywords for k in ['otp', 'pin', 'password', 'cvv', 'mpin']):
            scam_type = "OTP/credential theft scam"
        elif any(k in keywords for k in ['blocked', 'suspended', 'freeze', 'locked']):
            scam_type = "Account blocking fraud"
        elif any(k in keywords for k in ['lottery', 'prize', 'winner']):
            scam_type = "Lottery/prize scam"
        elif any(k in keywords for k in ['refund', 'cashback']):
            scam_type = "Refund/cashback fraud"
        elif any(k in keywords for k in ['kyc', 'pan', 'aadhar']):
            scam_type = "KYC verification scam"
        else:
            scam_type = "Financial fraud attempt"
        
        notes_parts.append(f"Scam type: {scam_type}.")
        
        # Determine tactics
        tactics = []
        if any(k in keywords for k in ['urgent', 'immediately', 'right now', 'hurry']):
            tactics.append("urgency")
        if any(k in keywords for k in ['blocked', 'suspended', 'warning', 'freeze', 'locked']):
            tactics.append("fear/threats")
        if any(k in keywords for k in ['verify', 'identity', 'security', 'authenticate']):
            tactics.append("impersonation")
        
        if tactics:
            notes_parts.append(f"Tactics: {', '.join(tactics)}.")
        
        # List extracted intelligence
        intel_parts = []
        if intelligence.phoneNumbers:
            intel_parts.append(f"Phone: {', '.join(intelligence.phoneNumbers[:3])}")
        if intelligence.upiIds:
            intel_parts.append(f"UPI: {', '.join(intelligence.upiIds[:3])}")
        if intelligence.phishingLinks:
            intel_parts.append(f"URL: {', '.join(intelligence.phishingLinks[:2])}")
        if intelligence.bankAccounts:
            intel_parts.append(f"Account: {', '.join(intelligence.bankAccounts[:2])}")
        
        if intel_parts:
            notes_parts.append(f"Extracted: {'; '.join(intel_parts)}.")
        
        return " ".join(notes_parts)
