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

    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract Indian bank account numbers."""
        patterns = [
            r'\b\d{9,18}\b',  # 9-18 digit account numbers
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Card-like format
        ]
        accounts = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            accounts.extend(matches)
        return list(set(accounts))

    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs (format: user@bankname or user@anything)."""
        # More permissive pattern to catch all UPI-like IDs
        pattern = r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\b'
        matches = re.findall(pattern, text.lower())
        
        # Known UPI bank suffixes
        upi_banks = [
            'upi', 'paytm', 'gpay', 'phonepe', 'ybl', 'oksbi', 'okaxis', 
            'okicici', 'okhdfcbank', 'axisbank', 'sbi', 'icici', 'hdfc',
            'ibl', 'axl', 'boi', 'pnb', 'kotak', 'indus', 'federal',
            'freecharge', 'amazonpay', 'apl', 'waaxis', 'wahdfcbank',
            'fam', 'ikwik', 'abfspay', 'pingpay', 'naviaxis', 'yesg',
            # Also catch suspicious/fake ones
            'fakebank', 'fake', 'fraud', 'scam', 'verify', 'secure',
            'bank', 'pay', 'money', 'cash', 'wallet'
        ]
        
        upi_ids = []
        for match in matches:
            # Skip obvious email domains
            email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'email.com']
            is_email = any(match.endswith(domain) for domain in email_domains)
            
            if not is_email:
                # Check if it contains a known UPI suffix OR has UPI-like structure
                suffix = match.split('@')[-1]
                if any(bank in suffix for bank in upi_banks) or len(suffix) <= 15:
                    upi_ids.append(match)
        
        return list(set(upi_ids))

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers."""
        patterns = [
            r'\+91[-\s]?\d{10}\b',  # +91 format
            r'\+91[-\s]?\d{5}[-\s]?\d{5}\b',  # +91-98765-43210 format
            r'\b91[-\s]?\d{10}\b',  # 91 prefix
            r'\b0\d{10}\b',  # 0 prefix (landline/mobile)
            r'\b[6-9]\d{9}\b',  # Indian mobile (starts with 6-9)
        ]
        phones = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            phones.extend(matches)
        
        # Normalize to +91 format
        normalized = []
        for phone in phones:
            clean = re.sub(r'[-\s]', '', phone)
            if clean.startswith('+91'):
                normalized.append(clean)
            elif clean.startswith('91') and len(clean) == 12:
                normalized.append('+' + clean)
            elif clean.startswith('0') and len(clean) == 11:
                normalized.append('+91' + clean[1:])
            elif len(clean) == 10:
                normalized.append('+91' + clean)
        return list(set(normalized))

    def extract_phishing_links(self, text: str) -> List[str]:
        """Extract suspicious URLs/links."""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        # Also check for shortened URLs and suspicious domains
        suspicious_patterns = [
            r'bit\.ly/\S+',
            r'tinyurl\.com/\S+',
            r'goo\.gl/\S+',
            r't\.co/\S+',
            r'cutt\.ly/\S+',
            r'shorturl\.\S+',
        ]
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(['http://' + m if not m.startswith('http') else m for m in matches])
        
        return list(set(urls))

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text."""
        suspicious_words = [
            "urgent", "immediately", "verify", "blocked", "suspended",
            "otp", "pin", "password", "cvv", "expire", "kyc", "pan",
            "aadhar", "lottery", "prize", "winner", "refund", "cashback",
            "claim", "free offer", "bonus", "reward", "unauthorized",
            "suspicious activity", "security alert", "warning", "freeze"
        ]
        text_lower = text.lower()
        found = []
        for word in suspicious_words:
            if word in text_lower:
                found.append(word)
        return list(set(found))

    def extract_all(self, messages: List[Dict]) -> ExtractedIntelligence:
        """Extract all intelligence from a list of messages."""
        all_text = " ".join([msg.get("text", "") for msg in messages])
        
        return ExtractedIntelligence(
            bankAccounts=self.extract_bank_accounts(all_text),
            upiIds=self.extract_upi_ids(all_text),
            phoneNumbers=self.extract_phone_numbers(all_text),
            phishingLinks=self.extract_phishing_links(all_text),
            suspiciousKeywords=self.extract_suspicious_keywords(all_text)
        )

    async def generate_agent_notes(self, messages: List[Dict]) -> str:
        """Generate summary notes about the scammer's behavior."""
        if not self.client:
            return "Scam conversation detected. Manual review recommended."

        # Only include scammer messages for analysis
        scammer_msgs = [m for m in messages if m.get('sender') == 'scammer']
        conversation = "\n".join([
            f"Scammer: {msg['text']}" for msg in scammer_msgs[-8:]
        ])

        prompt = f"""Analyze this scam conversation briefly.

Messages from scammer:
{conversation}

Write a 2-3 sentence summary covering:
1. Type of scam (bank fraud, UPI fraud, phishing)
2. Tactics used (urgency, fear, impersonation)
3. Key intelligence extracted (phone numbers, UPI IDs)

Be concise and factual."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=200  # Increased for complete response
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Failed to generate agent notes: {e}")
            return "Scam conversation detected. Automated analysis unavailable."
