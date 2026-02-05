"""Intelligence extraction from scam conversations."""

import re
from typing import List, Dict
from models import ExtractedIntelligence
from groq import Groq


class IntelligenceExtractor:
    """Extracts actionable intelligence from scam messages."""

    def __init__(self, api_key: str = None):
        """Initialize extractor with optional Groq API key."""
        self.api_key = api_key
        if api_key:
            self.client = Groq(api_key=api_key)
            self.model = "llama-3.3-70b-versatile"
        else:
            self.client = None

    def _normalize_text(self, text: str) -> str:
        """Normalize special characters in text."""
        # Replace various dash types with standard dash
        text = text.replace('–', '-')  # en-dash
        text = text.replace('—', '-')  # em-dash
        text = text.replace('−', '-')  # minus sign
        return text

    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract Indian bank account numbers (9-18 digits)."""
        text = self._normalize_text(text)
        
        # Find 9-18 digit numbers that look like account numbers
        pattern = r'\b(\d{9,18})\b'
        matches = re.findall(pattern, text)
        
        # Also look for card-format numbers
        card_pattern = r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b'
        card_matches = re.findall(card_pattern, text)
        matches.extend([re.sub(r'[-\s]', '', m) for m in card_matches])
        
        # Filter out likely phone numbers (10-digit starting with 6-9 or 91)
        accounts = []
        for m in matches:
            # Skip if it's a 10-digit number starting with 6-9 (phone)
            if len(m) == 10 and m[0] in '6789':
                continue
            # Skip if it's 91 + 10 digits (phone with country code)
            if len(m) == 12 and m.startswith('91') and m[2] in '6789':
                continue
            accounts.append(m)
        
        return list(set(accounts))

    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs (format: something@something)."""
        text = self._normalize_text(text.lower())
        
        # Match any word@word pattern
        pattern = r'([a-zA-Z0-9][a-zA-Z0-9._-]*@[a-zA-Z0-9][a-zA-Z0-9._-]*)'
        matches = re.findall(pattern, text)
        
        # Email TLDs to filter out
        email_tlds = ['.com', '.org', '.net', '.in', '.co', '.io', '.edu', '.gov', '.info', '.biz']
        
        # Common email domains to filter out  
        email_domains = [
            'gmail', 'yahoo', 'hotmail', 'outlook', 'email', 'mail', 
            'protonmail', 'icloud', 'live', 'msn', 'aol', 'rediffmail',
            'zoho', 'yandex', 'tutanota', 'fastmail', 'pm', 'hey'
        ]
        
        upi_ids = []
        for match in matches:
            # Strip trailing punctuation
            match = match.rstrip('.,;:!?')
            suffix = match.split('@')[-1]
            
            # Skip if it looks like an email (has common TLD)
            if any(suffix.endswith(tld) for tld in email_tlds):
                continue
            
            # Skip if domain part matches common email providers
            if any(domain in suffix for domain in email_domains):
                continue
            
            upi_ids.append(match)
        
        return list(set(upi_ids))

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers."""
        text = self._normalize_text(text)
        
        phones = []
        
        # Pattern 1: +91 followed by 10 digits (with optional spaces/dashes)
        pattern1 = r'\+91[-\s]?(\d{5})[-\s]?(\d{5})'
        for match in re.finditer(pattern1, text):
            phones.append('+91' + match.group(1) + match.group(2))
        
        # Pattern 2: +91 followed by 10 digits (continuous)
        pattern2 = r'\+91[-\s]?(\d{10})\b'
        for match in re.finditer(pattern2, text):
            phones.append('+91' + match.group(1))
        
        # Pattern 3: 91 followed by 10 digits
        pattern3 = r'\b91[-\s]?(\d{10})\b'
        for match in re.finditer(pattern3, text):
            phones.append('+91' + match.group(1))
        
        # Pattern 4: 10-digit Indian mobile (starting with 6-9)
        pattern4 = r'\b([6-9]\d{9})\b'
        for match in re.finditer(pattern4, text):
            # Avoid matching if it's part of a longer number
            phones.append('+91' + match.group(1))
        
        return list(set(phones))

    def extract_phishing_links(self, text: str) -> List[str]:
        """Extract URLs/links from text."""
        text = self._normalize_text(text)
        
        urls = []
        
        # Pattern 1: http:// or https:// URLs
        pattern1 = r'(https?://[^\s<>"\']+)'
        for match in re.finditer(pattern1, text, re.IGNORECASE):
            url = match.group(1).rstrip('.,;:!?)\'\"')
            urls.append(url)
        
        # Pattern 2: www. URLs (add https://)
        pattern2 = r'\b(www\.[^\s<>"\']+)'
        for match in re.finditer(pattern2, text, re.IGNORECASE):
            url = match.group(1).rstrip('.,;:!?)\'\"')
            urls.append('https://' + url)
        
        # Pattern 3: Common URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'cutt.ly', 'shorturl.at']
        for shortener in shorteners:
            pattern = rf'({re.escape(shortener)}/[^\s<>"\']+)'
            for match in re.finditer(pattern, text, re.IGNORECASE):
                url = match.group(1).rstrip('.,;:!?)\'\"')
                if not url.startswith('http'):
                    url = 'https://' + url
                urls.append(url)
        
        return list(set(urls))

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text."""
        suspicious_words = [
            "urgent", "immediately", "verify", "blocked", "suspended",
            "otp", "pin", "password", "cvv", "expire", "kyc", "pan",
            "aadhar", "lottery", "prize", "winner", "refund", "cashback",
            "claim", "bonus", "reward", "unauthorized", "warning", "freeze",
            "compromised", "secure", "identity", "verify now", "account blocked"
        ]
        
        text_lower = text.lower()
        found = []
        for word in suspicious_words:
            if word in text_lower:
                found.append(word)
        
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
        # Extract intelligence from messages if not provided
        if intelligence is None:
            intelligence = self.extract_all(messages)
        
        # Build factual summary based on extracted data
        notes_parts = []
        
        # Determine scam type based on keywords
        keywords = intelligence.suspiciousKeywords
        if any(k in keywords for k in ['otp', 'pin', 'password', 'cvv']):
            scam_type = "OTP/credential theft scam"
        elif any(k in keywords for k in ['blocked', 'suspended', 'freeze']):
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
        
        # Tactics used
        tactics = []
        if any(k in keywords for k in ['urgent', 'immediately']):
            tactics.append("urgency")
        if any(k in keywords for k in ['blocked', 'suspended', 'warning']):
            tactics.append("fear/threats")
        if any(k in keywords for k in ['verify', 'identity', 'secure']):
            tactics.append("impersonation")
        
        if tactics:
            notes_parts.append(f"Tactics used: {', '.join(tactics)}.")
        
        # Extracted intelligence
        intel_parts = []
        if intelligence.phoneNumbers:
            intel_parts.append(f"phone: {', '.join(intelligence.phoneNumbers[:2])}")
        if intelligence.upiIds:
            intel_parts.append(f"UPI: {', '.join(intelligence.upiIds[:2])}")
        if intelligence.phishingLinks:
            intel_parts.append(f"link: {intelligence.phishingLinks[0]}")
        if intelligence.bankAccounts:
            intel_parts.append(f"account: {intelligence.bankAccounts[0]}")
        
        if intel_parts:
            notes_parts.append(f"Extracted: {'; '.join(intel_parts)}.")
        
        return " ".join(notes_parts)
