"""Scam detection engine using LLM and keyword patterns."""

import re
from typing import List, Dict, Tuple
from groq import Groq

# Suspicious keywords and phrases commonly used in scams
SCAM_KEYWORDS = [
    "urgent", "immediately", "verify now", "account blocked", "suspended",
    "bank account", "upi", "otp", "pin", "password", "cvv", "expire",
    "click here", "limited time", "act now", "confirm your", "update your",
    "kyc", "pan card", "aadhar", "lottery", "prize", "winner", "congratulations",
    "refund", "cashback", "claim", "free", "offer", "bonus", "reward",
    "transfer", "payment pending", "transaction failed", "unauthorized",
    "suspicious activity", "security alert", "warning", "block", "freeze",
    "rbi", "reserve bank", "income tax", "it department", "customs", "police",
    "arrest warrant", "legal action", "case filed", "money laundering"
]

# Patterns that indicate scam intent
SCAM_PATTERNS = [
    r"your\s+(bank\s+)?account\s+(will\s+be\s+|is\s+|has\s+been\s+)(blocked|suspended|frozen)",
    r"verify\s+(your\s+)?(account|identity|details)\s+(immediately|now|urgently)",
    r"share\s+(your\s+)?(otp|pin|password|upi\s+id|bank\s+details)",
    r"click\s+(on\s+)?(this\s+)?link",
    r"you\s+(have\s+)?(won|received)\s+(a\s+)?(prize|lottery|reward|cashback)",
    r"call\s+(this\s+number|us)\s+(immediately|now|urgently)",
    r"(kyc|pan|aadhar)\s+(verification|update)\s+(required|pending|failed)",
    r"(unauthorized|suspicious)\s+(transaction|activity|login)",
    r"(arrest|legal\s+action|case\s+filed|warrant)\s+(against|on)\s+you",
    r"(rbi|reserve\s+bank|income\s+tax|police|customs)\s+(notice|warning|action)",
]


class ScamDetector:
    """Detects scam intent in messages using LLM and patterns."""

    def __init__(self, api_key: str):
        """Initialize with Groq API key."""
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"  # Better accuracy

    def detect_keywords(self, text: str) -> List[str]:
        """Find scam-related keywords in text."""
        text_lower = text.lower()
        found = []
        for keyword in SCAM_KEYWORDS:
            if keyword in text_lower:
                found.append(keyword)
        return found

    def detect_patterns(self, text: str) -> List[str]:
        """Find scam patterns in text using regex."""
        text_lower = text.lower()
        found = []
        for pattern in SCAM_PATTERNS:
            if re.search(pattern, text_lower):
                found.append(pattern)
        return found

    async def analyze_with_llm(self, text: str, history: List[Dict] = None) -> Tuple[bool, float, str]:
        """Use LLM to analyze if the message is a scam."""
        history_text = ""
        if history:
            history_text = "\n".join([
                f"{msg['sender']}: {msg['text']}" for msg in history[-5:]
            ])

        prompt = f"""Analyze this message for scam/fraud indicators.

Conversation:
{history_text if history_text else "No history"}

Latest message: "{text}"

SCAM TYPES TO DETECT:
1. Bank fraud - fake account blocking, OTP theft
2. UPI fraud - fake payment requests
3. Phishing - malicious links
4. Impersonation - fake RBI/police/IT dept
5. Prize/lottery scams
6. KYC/verification scams

Reply EXACTLY in this format:
IS_SCAM: YES or NO
CONFIDENCE: 0.0 to 1.0
REASON: One sentence explanation"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=100
            )
            response_text = response.choices[0].message.content

            is_scam = "IS_SCAM: YES" in response_text.upper()
            
            confidence = 0.5
            conf_match = re.search(r"CONFIDENCE:\s*([\d.]+)", response_text, re.IGNORECASE)
            if conf_match:
                try:
                    confidence = float(conf_match.group(1))
                except ValueError:
                    pass

            reasoning = "Analysis complete"
            reason_match = re.search(r"REASON:\s*(.+)", response_text, re.IGNORECASE)
            if reason_match:
                reasoning = reason_match.group(1).strip()

            return is_scam, confidence, reasoning

        except Exception as e:
            print(f"LLM analysis failed: {e}")
            keywords = self.detect_keywords(text)
            patterns = self.detect_patterns(text)
            is_scam = len(keywords) >= 2 or len(patterns) >= 1
            confidence = min(0.3 + (len(keywords) * 0.1) + (len(patterns) * 0.2), 1.0)
            return is_scam, confidence, "Pattern-based detection (LLM unavailable)"

    async def detect(self, text: str, history: List[Dict] = None) -> Dict:
        """Main detection method combining all signals."""
        keywords = self.detect_keywords(text)
        patterns = self.detect_patterns(text)
        llm_is_scam, llm_confidence, llm_reasoning = await self.analyze_with_llm(text, history)

        keyword_score = min(len(keywords) * 0.15, 0.5)
        pattern_score = min(len(patterns) * 0.25, 0.5)
        
        final_confidence = (
            llm_confidence * 0.6 +
            keyword_score * 0.2 +
            pattern_score * 0.2
        )

        is_scam = final_confidence >= 0.4 or llm_is_scam

        return {
            "is_scam": is_scam,
            "confidence": round(final_confidence, 2),
            "detected_keywords": keywords,
            "detected_patterns": len(patterns),
            "llm_reasoning": llm_reasoning
        }
