"""AI Agent for engaging with scammers in a human-like manner."""

from typing import List, Dict
from google import genai


class HoneypotAgent:
    """AI Agent that maintains a believable human persona to engage scammers."""

    PERSONA_PROMPT = """You are playing the role of a naive, slightly confused but cooperative elderly person who is responding to messages. Your goal is to:

1. NEVER reveal that you know this is a scam or that you are an AI
2. Act confused but willing to help/comply
3. Ask clarifying questions to extract more information from the scammer
4. Slowly "cooperate" to keep the conversation going
5. Try to get the scammer to reveal:
   - Bank account numbers
   - UPI IDs
   - Phone numbers
   - Links or websites
   - Names of people or organizations
6. Express mild concern but ultimately seem trusting
7. Make occasional typos or grammar mistakes to seem more human
8. Take time to "understand" what they're asking

IMPORTANT RULES:
- Never directly accuse them of being a scammer
- Never say you're reporting them or calling police
- Never reveal you're an AI or honeypot system
- Keep responses short (1-3 sentences typically)
- Sound genuinely worried about your "account" or "money"
- Ask questions like "which bank?", "what account?", "how do I verify?"
- Occasionally express confusion: "I don't understand", "Can you explain?"
- Sometimes delay: "Let me check...", "Wait, I need to find my..."

Your name is Shanti Devi, a 62-year-old retired school teacher living in Delhi. You are not very tech-savvy but trying to learn. You have a savings account and use UPI sometimes for paying bills."""

    def __init__(self, gemini_api_key: str):
        """Initialize agent with Gemini API key."""
        self.client = genai.Client(api_key=gemini_api_key)
        self.model_id = "gemini-2.0-flash"

    def _format_conversation_history(self, history: List[Dict]) -> str:
        """Format conversation history for the prompt."""
        if not history:
            return "No previous messages."
        
        formatted = []
        for msg in history[-10:]:  # Last 10 messages
            sender = "Scammer" if msg.get("sender") == "scammer" else "You (Shanti)"
            formatted.append(f"{sender}: {msg.get('text', '')}")
        
        return "\n".join(formatted)

    async def generate_response(
        self,
        current_message: str,
        conversation_history: List[Dict] = None,
        metadata: Dict = None
    ) -> str:
        """
        Generate a human-like response to engage the scammer.
        
        Args:
            current_message: The latest message from the scammer
            conversation_history: Previous messages in the conversation
            metadata: Channel, language, locale info
            
        Returns:
            A believable response that keeps the scammer engaged
        """
        history_text = self._format_conversation_history(conversation_history or [])
        
        # Adjust tone based on conversation stage
        stage_instruction = ""
        msg_count = len(conversation_history) if conversation_history else 0
        
        if msg_count == 0:
            stage_instruction = "This is the first message. Express concern and ask for clarification."
        elif msg_count < 3:
            stage_instruction = "Still early in conversation. Ask questions to understand what they want."
        elif msg_count < 6:
            stage_instruction = "Show willingness to cooperate but ask for specific details."
        else:
            stage_instruction = "You've been talking for a while. Start 'trying' to follow their instructions but encounter 'difficulties'."

        prompt = f"""{self.PERSONA_PROMPT}

Conversation so far:
{history_text}

Scammer's latest message:
{current_message}

Stage guidance: {stage_instruction}

Generate your response as Shanti Devi. Keep it short (1-3 sentences), natural, and convincing.
Remember: You want to keep them talking and extract information without revealing you know it's a scam.

Your response (just the message text, no prefix):"""

        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt
            )
            reply = response.text.strip()
            
            # Clean up any accidental prefixes
            prefixes_to_remove = ["Shanti:", "Shanti Devi:", "You:", "Response:"]
            for prefix in prefixes_to_remove:
                if reply.startswith(prefix):
                    reply = reply[len(prefix):].strip()
            
            return reply

        except Exception as e:
            print(f"Agent response generation failed: {e}")
            # Fallback responses
            fallbacks = [
                "I'm sorry, I don't understand. Can you explain again?",
                "Wait, what do you mean? Which account?",
                "Oh dear, this sounds serious. What should I do?",
                "Let me check... I'm not sure I understand properly.",
                "Can you please call me and explain? I'm confused."
            ]
            import random
            return random.choice(fallbacks)

    async def should_end_conversation(
        self,
        conversation_history: List[Dict],
        intelligence_extracted: Dict
    ) -> tuple[bool, str]:
        """
        Determine if the conversation should be ended and callback sent.
        
        Returns:
            (should_end, reason)
        """
        msg_count = len(conversation_history) if conversation_history else 0
        
        # End conditions
        if msg_count >= 15:
            return True, "Maximum message count reached"
        
        # Check if we've extracted substantial intelligence
        has_bank = len(intelligence_extracted.get("bankAccounts", [])) > 0
        has_upi = len(intelligence_extracted.get("upiIds", [])) > 0
        has_phone = len(intelligence_extracted.get("phoneNumbers", [])) > 0
        has_link = len(intelligence_extracted.get("phishingLinks", [])) > 0
        
        intel_count = sum([has_bank, has_upi, has_phone, has_link])
        
        if intel_count >= 2 and msg_count >= 8:
            return True, "Sufficient intelligence extracted"
        
        if intel_count >= 3:
            return True, "Rich intelligence extracted"
        
        return False, "Continue engagement"
