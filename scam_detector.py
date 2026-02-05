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
    "suspicious activity", "security alert", "warning", "block", "freeze"
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
]


class ScamDetector:
    """Detects scam intent in messages using LLM and patterns."""

    def __init__(self, api_key: str):
        """Initialize with Groq API key."""
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.1-8b-instant"  # Fast and free

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
        """
        Use LLM to analyze if the message is a scam.
        Returns: (is_scam, confidence, reasoning)
        """
        history_text = ""
        if history:
            history_text = "\n".join([
                f"{msg['sender']}: {msg['text']}" for msg in history[-5:]
            ])

        prompt = f"""You are a scam detection expert. Analyze the following message and conversation history to determine if this is a scam attempt.

Conversation History:
{history_text if history_text else "No previous history"}

Latest Message:
{text}

Common scam tactics include:
- Bank fraud: claiming account will be blocked, asking for OTP/PIN
- UPI fraud: asking for UPI ID or payment links
- Phishing: fake links, impersonating banks/companies
- Urgency tactics: "act now", "immediate action required"
- Prize/lottery scams: claiming you've won something

Respond in this exact format:
IS_SCAM: [YES/NO]
CONFIDENCE: [0.0-1.0]
REASONING: [Brief explanation]

Be conservative - if unsure, lean towards detecting as scam to protect users."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=200
            )
            response_text = response.choices[0].message.content

            # Parse response
            is_scam = "IS_SCAM: YES" in response_text.upper()
            
            # Extract confidence
            confidence = 0.5
            if "CONFIDENCE:" in response_text.upper():
                try:
                    conf_match = re.search(r"CONFIDENCE:\s*([\d.]+)", response_text, re.IGNORECASE)
                    if conf_match:
                        confidence = float(conf_match.group(1))
                except ValueError:
                    pass

            # Extract reasoning
            reasoning = "Unable to determine reasoning"
            if "REASONING:" in response_text.upper():
                reason_match = re.search(r"REASONING:\s*(.+)", response_text, re.IGNORECASE | re.DOTALL)
                if reason_match:
                    reasoning = reason_match.group(1).strip()

            return is_scam, confidence, reasoning

        except Exception as e:
            # Fallback to pattern-based detection if LLM fails
            print(f"LLM analysis failed: {e}")
            keywords = self.detect_keywords(text)
            patterns = self.detect_patterns(text)
            is_scam = len(keywords) >= 2 or len(patterns) >= 1
            confidence = min(0.3 + (len(keywords) * 0.1) + (len(patterns) * 0.2), 1.0)
            return is_scam, confidence, "Pattern-based detection (LLM unavailable)"

    async def detect(self, text: str, history: List[Dict] = None) -> Dict:
        """
        Main detection method combining keyword, pattern, and LLM analysis.
        Returns detection result with confidence and details.
        """
        keywords = self.detect_keywords(text)
        patterns = self.detect_patterns(text)
        llm_is_scam, llm_confidence, llm_reasoning = await self.analyze_with_llm(text, history)

        # Combine signals
        keyword_score = min(len(keywords) * 0.15, 0.5)
        pattern_score = min(len(patterns) * 0.25, 0.5)
        
        # Weighted combination
        final_confidence = (
            llm_confidence * 0.6 +  # LLM gets highest weight
            keyword_score * 0.2 +
            pattern_score * 0.2
        )

        # Final decision
        is_scam = final_confidence >= 0.4 or llm_is_scam

        return {
            "is_scam": is_scam,
            "confidence": round(final_confidence, 2),
            "detected_keywords": keywords,
            "detected_patterns": len(patterns),
            "llm_reasoning": llm_reasoning
        }
