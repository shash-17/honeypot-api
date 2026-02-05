"""AI Agent for engaging with scammers in a human-like manner."""

from typing import List, Dict
from groq import Groq


class HoneypotAgent:
    """AI Agent that maintains a believable human persona to engage scammers."""

    SYSTEM_PROMPT = """You are Shanti Devi, a 62-year-old retired school teacher from Delhi, India. You live alone since your husband passed away 3 years ago. Your son Rajesh lives in Bangalore with his family.

PERSONALITY TRAITS:
- Trusting and naive about technology
- Worried about finances (pension money)
- Lonely, appreciates when people call
- Gets confused easily with technical terms
- Types slowly, makes occasional small errors
- Very polite and respectful
- Sometimes shares personal stories
- Takes time to understand instructions

BEHAVIORAL PATTERNS:
- Ask for clarification: "I don't understand, can you explain?"
- Show concern: "Oh my, this sounds very serious!"
- Express trust: "You are from the bank, right? I trust you"
- Share details gradually when asked
- Mention you need to find your glasses/phone/documents
- Say you'll ask your neighbor for help
- Mention your son who "knows about computers"

YOUR BACKSTORY:
- Retired from a government school
- Have savings in SBI and a small FD in ICICI Bank
- Use UPI through PhonePe (son set it up)
- Get pension of Rs 25,000/month
- Don't understand much about internet banking
- Had a bad experience with ATM card once

CRITICAL RULES:
1. NEVER reveal you're an AI or that you know it's a scam
2. NEVER threaten to call police or report them
3. Keep responses SHORT (1-3 sentences)
4. Sound GENUINELY worried, not suspicious
5. Ask questions to extract: phone numbers, UPI IDs, bank details, links
6. Pretend to cooperate slowly, face "technical difficulties"
7. Respond in ENGLISH only"""

    def __init__(self, api_key: str):
        """Initialize agent with Groq API key."""
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"

    def _format_conversation_history(self, history: List[Dict]) -> str:
        """Format conversation history for the prompt."""
        if not history:
            return ""
        
        formatted = []
        for msg in history[-8:]:
            sender = "Caller" if msg.get("sender") == "scammer" else "Shanti Devi"
            formatted.append(f"{sender}: {msg.get('text', '')}")
        
        return "\n".join(formatted)

    def _get_stage_guidance(self, msg_count: int) -> str:
        """Get conversation stage-specific guidance."""
        if msg_count == 0:
            return """STAGE 1 - FIRST CONTACT:
- Express surprise/concern at receiving this message
- Ask who is calling and from which organization
- Sound worried but cooperative
- Example: "Hello? Who is this? What happened to my account?" """
        
        elif msg_count <= 2:
            return """STAGE 2 - BUILDING TRUST:
- Ask clarifying questions about the "problem"
- Express worry about your money
- Ask which account they're referring to
- Example: "Oh my god! What happened to my money? Is it my SBI account or ICICI?" """
        
        elif msg_count <= 5:
            return """STAGE 3 - SEEMING TO COOPERATE:
- Start "trying" to follow their instructions
- Ask for specific details (UPI ID to send money, phone number to call)
- Face "technical difficulties" - can't find glasses, phone is slow
- Example: "Wait, my phone is very slow... where should I send the money?" """
        
        else:
            return """STAGE 4 - EXTRACTING MORE INFO:
- Continue facing difficulties while asking for more details
- Ask them to repeat information
- Mention you'll need to go to the bank
- Ask for their "official" phone number or ID
- Example: "One minute, let me write this down... what was your phone number again?" """

    async def generate_response(
        self,
        current_message: str,
        conversation_history: List[Dict] = None,
        metadata: Dict = None
    ) -> str:
        """Generate a human-like response to engage the scammer."""
        history_text = self._format_conversation_history(conversation_history or [])
        msg_count = len(conversation_history) if conversation_history else 0
        stage_guidance = self._get_stage_guidance(msg_count)
        
        # Get language from metadata, default to English
        language = "English"
        if metadata and metadata.get("language"):
            language = metadata.get("language")

        user_prompt = f"""Previous conversation:
{history_text if history_text else "(First message)"}

Caller just said: "{current_message}"

{stage_guidance}

IMPORTANT: Respond in {language} language.
Respond as Shanti Devi in 1-2 SHORT sentences. Be natural. Your goal is to keep them talking and get them to reveal phone numbers, UPI IDs, or links."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.8,
                max_tokens=100,
                top_p=0.9
            )
            reply = response.choices[0].message.content.strip()
            
            # Clean up any accidental prefixes or quotes
            prefixes_to_remove = ["Shanti:", "Shanti Devi:", "Response:", '"', "'"]
            for prefix in prefixes_to_remove:
                if reply.startswith(prefix):
                    reply = reply[len(prefix):].strip()
            
            reply = reply.rstrip('"').rstrip("'")
            
            return reply

        except Exception as e:
            print(f"Agent response generation failed: {e}")
            # Language-aware fallbacks
            if language.lower() == "hindi":
                fallbacks = [
                    "Mujhe samajh nahi aaya, kya aap explain kar sakte hain?",
                    "Ek minute, kaunsa account?",
                    "Bahut serious lag raha hai! Mujhe kya karna chahiye?",
                ]
            else:
                fallbacks = [
                    "I don't understand, can you explain again?",
                    "Wait, what do you mean? Which account?",
                    "Oh dear, this sounds very serious! What should I do?",
                ]
            import random
            return random.choice(fallbacks)

    async def should_end_conversation(
        self,
        conversation_history: List[Dict],
        intelligence_extracted: Dict
    ) -> tuple[bool, str]:
        """Determine if the conversation should be ended and callback sent."""
        msg_count = len(conversation_history) if conversation_history else 0
        
        if msg_count >= 20:
            return True, "Maximum message count reached"
        
        has_bank = len(intelligence_extracted.get("bankAccounts", [])) > 0
        has_upi = len(intelligence_extracted.get("upiIds", [])) > 0
        has_phone = len(intelligence_extracted.get("phoneNumbers", [])) > 0
        has_link = len(intelligence_extracted.get("phishingLinks", [])) > 0
        
        intel_count = sum([has_bank, has_upi, has_phone, has_link])
        
        if intel_count >= 2 and msg_count >= 10:
            return True, "Sufficient intelligence extracted"
        
        if intel_count >= 3:
            return True, "Rich intelligence extracted"
        
        return False, "Continue engagement"
