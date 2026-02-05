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
        """Extract UPI IDs (format: user@anything)."""
        # Permissive pattern - any word@word format
        pattern = r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\b'
        matches = re.findall(pattern, text.lower())
        
        # Filter out obvious emails
        email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                         'email.com', 'mail.com', 'protonmail.com', 'icloud.com']
        
        upi_ids = []
        for match in matches:
            is_email = any(match.endswith(domain) for domain in email_domains)
            if not is_email:
                upi_ids.append(match)
        
        return list(set(upi_ids))

    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers."""
        # Normalize text - replace various dash types with standard dash
        normalized_text = text.replace('–', '-').replace('—', '-').replace('−', '-')
        
        patterns = [
            r'\+91[-\s]?\d{10}\b',
            r'\+91[-\s]?\d{5}[-\s]?\d{5}\b',
            r'\b91[-\s]?\d{10}\b',
            r'\b0\d{10}\b',
            r'\b[6-9]\d{9}\b',
        ]
        phones = []
        for pattern in patterns:
            matches = re.findall(pattern, normalized_text)
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
        """Extract all URLs/links from text."""
        # Normalize dashes and special characters
        normalized_text = text.replace('–', ' ').replace('—', ' ').replace('−', ' ')
        
        # Multiple URL patterns for comprehensive matching
        patterns = [
            r'https?://[^\s<>"\'{}|\\^`\[\]]+',  # Standard URLs
            r'www\.[^\s<>"\'{}|\\^`\[\]]+',      # www. URLs without protocol
            r'bit\.ly/[^\s]+',
            r'tinyurl\.com/[^\s]+',
            r'goo\.gl/[^\s]+',
            r't\.co/[^\s]+',
            r'cutt\.ly/[^\s]+',
        ]
        
        urls = []
        for pattern in patterns:
            matches = re.findall(pattern, normalized_text, re.IGNORECASE)
            for match in matches:
                # Clean trailing punctuation
                clean_url = match.rstrip('.,;:!?)\'\"')
                if clean_url.startswith('www.'):
                    clean_url = 'https://' + clean_url
                urls.append(clean_url)
        
        return list(set(urls))

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text."""
        suspicious_words = [
            "urgent", "immediately", "verify", "blocked", "suspended",
            "otp", "pin", "password", "cvv", "expire", "kyc", "pan",
            "aadhar", "lottery", "prize", "winner", "refund", "cashback",
            "claim", "free offer", "bonus", "reward", "unauthorized",
            "suspicious activity", "security alert", "warning", "freeze",
            "compromised", "secure", "identity", "account number"
        ]
        text_lower = text.lower()
        found = []
        for word in suspicious_words:
            if word in text_lower:
                found.append(word)
        return list(set(found))

    async def extract_with_llm(self, messages: List[Dict]) -> Dict:
        """Use LLM to extract intelligence that patterns might miss."""
        if not self.client:
            return {}
        
        all_text = " ".join([msg.get("text", "") for msg in messages])
        
        prompt = f"""Extract the following from this conversation. Return ONLY valid items found, nothing else.

Text: {all_text[:2000]}

Find and list:
1. PHONE_NUMBERS: Any phone numbers (Indian format +91, 10 digits, etc.)
2. UPI_IDS: Any UPI IDs (format: something@something)
3. URLS: Any website links or URLs
4. BANK_ACCOUNTS: Any bank account numbers (long digit sequences)

Format your response EXACTLY like this (one item per line):
PHONE: +919876543210
UPI: example@bank
URL: https://example.com
ACCOUNT: 1234567890123

Only list items that are actually present. If none found for a category, skip it."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=300
            )
            result = response.choices[0].message.content
            
            extracted = {
                "phones": [],
                "upis": [],
                "urls": [],
                "accounts": []
            }
            
            for line in result.split('\n'):
                line = line.strip()
                if line.startswith('PHONE:'):
                    extracted["phones"].append(line.replace('PHONE:', '').strip())
                elif line.startswith('UPI:'):
                    extracted["upis"].append(line.replace('UPI:', '').strip())
                elif line.startswith('URL:'):
                    extracted["urls"].append(line.replace('URL:', '').strip())
                elif line.startswith('ACCOUNT:'):
                    extracted["accounts"].append(line.replace('ACCOUNT:', '').strip())
            
            return extracted
        except Exception as e:
            print(f"LLM extraction failed: {e}")
            return {}

    def extract_all(self, messages: List[Dict]) -> ExtractedIntelligence:
        """Extract all intelligence from a list of messages."""
        all_text = " ".join([msg.get("text", "") for msg in messages])
        
        # Pattern-based extraction
        bank_accounts = self.extract_bank_accounts(all_text)
        upi_ids = self.extract_upi_ids(all_text)
        phone_numbers = self.extract_phone_numbers(all_text)
        phishing_links = self.extract_phishing_links(all_text)
        keywords = self.extract_suspicious_keywords(all_text)
        
        return ExtractedIntelligence(
            bankAccounts=bank_accounts,
            upiIds=upi_ids,
            phoneNumbers=phone_numbers,
            phishingLinks=phishing_links,
            suspiciousKeywords=keywords
        )

    async def generate_agent_notes(self, messages: List[Dict]) -> str:
        """Generate summary notes about the scammer's behavior."""
        if not self.client:
            return "Scam conversation detected. Manual review recommended."

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
3. Key intelligence extracted (phone numbers, UPI IDs, links)

Be concise and factual."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Failed to generate agent notes: {e}")
            return "Scam conversation detected. Automated analysis unavailable."
