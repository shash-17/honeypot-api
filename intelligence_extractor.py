"""Intelligence extraction from scam conversations."""

import re
from typing import List, Dict
from models import ExtractedIntelligence
from google import genai


class IntelligenceExtractor:
    """Extracts actionable intelligence from scam messages."""

    def __init__(self, gemini_api_key: str = None):
        """Initialize extractor with optional Gemini API key."""
        self.gemini_api_key = gemini_api_key
        if gemini_api_key:
            self.client = genai.Client(api_key=gemini_api_key)
            self.model_id = "gemini-2.0-flash"
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
        """Extract UPI IDs (format: user@bankname)."""
        pattern = r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b'
        matches = re.findall(pattern, text.lower())
        # Filter to likely UPI IDs (common bank suffixes)
        upi_banks = ['upi', 'paytm', 'gpay', 'phonepe', 'ybl', 'oksbi', 'okaxis', 
                     'okicici', 'okhdfcbank', 'axisbank', 'sbi', 'icici', 'hdfc',
                     'ibl', 'axl', 'boi', 'pnb', 'kotak', 'indus', 'federal']
        upi_ids = []
        for match in matches:
            suffix = match.split('@')[-1]
            if any(bank in suffix for bank in upi_banks):
                upi_ids.append(match)
        return list(set(upi_ids))

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers."""
        patterns = [
            r'\+91[-\s]?\d{10}\b',  # +91 format
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
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        # Also check for shortened URLs and suspicious domains
        suspicious_patterns = [
            r'bit\.ly/\S+',
            r'tinyurl\.com/\S+',
            r'goo\.gl/\S+',
            r't\.co/\S+',
            r'cutt\.ly/\S+',
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
            # Fallback without LLM
            return "Scam conversation detected. Manual review recommended."

        conversation = "\n".join([
            f"{msg['sender']}: {msg['text']}" for msg in messages
        ])

        prompt = f"""Analyze this scam conversation and provide a brief summary of the scammer's tactics and behavior.

Conversation:
{conversation}

Provide a 1-2 sentence summary focusing on:
- Type of scam (bank fraud, UPI fraud, phishing, etc.)
- Tactics used (urgency, fear, impersonation, etc.)
- Any notable patterns or intelligence

Keep the response concise, under 100 words."""

        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            print(f"Failed to generate agent notes: {e}")
            return "Scam conversation detected. Automated analysis unavailable."
