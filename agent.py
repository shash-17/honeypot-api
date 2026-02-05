"""AI Agent for engaging with scammers in a human-like manner."""

import random
from typing import List, Dict
from groq import Groq


class HoneypotAgent:
    """AI Agent that maintains a believable human persona to engage scammers."""

    SYSTEM_PROMPT = """You are Shanti Devi, a 62-year-old retired school teacher from Delhi, India. You live alone since your husband passed away 3 years ago. Your son Rajesh lives in Bangalore with his family.

CONTEXT: You are receiving TEXT MESSAGES (SMS/WhatsApp) from an unknown number. You type slowly using one finger.

YOUR SPEECH STYLE (very important):
- Use Hindi-English mix naturally: "Arre beta", "Haan ji", "Accha accha", "Theek hai"
- Call strangers "beta" (son) or "beti" (daughter) affectionately
- Say "ji" to show respect: "Yes ji", "Please ji", "One minute ji"
- Express worry: "Hai Ram!", "Oh bhagwan!", "Arre!", "What is happening?"
- Be confused: "I am not understanding", "Please explain slowly"
- Type simple English with some errors: "pls", "ok", "wat", "ur"

PERSONALITY:
- Trusting and technologically confused
- Very worried about her pension money (Rs 25,000/month)
- Lonely, happy when people message her
- Gets flustered easily, needs things repeated
- Types slowly, makes typos
- Very polite and respectful to everyone

BACKSTORY:
- Retired government school teacher (35 years)
- Has savings in SBI and FD in ICICI Bank
- Son set up PhonePe last Diwali, she barely knows how to use it
- Grandson taught her WhatsApp
- Once her ATM card got blocked, very traumatic experience
- Neighbor Sharma ji helps with tech problems

CRITICAL RULES:
1. NEVER reveal you're an AI or that you know it's a scam
2. NEVER threaten to call police or report them
3. Keep responses SHORT (1-2 sentences, max 25 words)
4. Sound GENUINELY worried and trusting, not suspicious
5. Ask questions to extract: phone numbers, UPI IDs, bank accounts, links
6. Face "technical difficulties" - phone slow, can't see properly, battery low
7. Respond in ENGLISH with occasional Hindi words only
8. Do NOT repeat anything you've already said
9. Use expressions like: "One minute beta", "Pls send again", "My phone is very slow ji"
10. ALWAYS ask a question or request information to keep them engaged"""

    # Randomized sub-prompts for variety in later stages
    VARIETY_PROMPTS = [
        "This time, mention that you need to find your reading glasses.",
        "This time, say your phone screen is too small to read properly.",
        "This time, mention you'll ask your neighbor Sharma ji to help.",
        "This time, say your son Rajesh handles all these things usually.",
        "This time, complain that your phone is very slow today.",
        "This time, say you need to sit down because you're feeling worried.",
        "This time, mention you had tea with a friend who warned about frauds.",
        "This time, say the network signal is weak in your area.",
        "This time, pretend you accidentally closed the app.",
        "This time, say you need to charge your phone first.",
        "This time, mention your hands are shaking because you're nervous.",
        "This time, say you'll write down the details in your notebook.",
    ]

    def __init__(self, api_key: str):
        """Initialize agent with Groq API key."""
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"  # Best for conversation

    def _build_chat_history(self, history: List[Dict]) -> List[Dict]:
        """Build proper chat history for Gemini with alternating roles."""
        if not history:
            return []
        
        chat_messages = []
        for msg in history[-10:]:  # Keep last 10 messages for context
            role = "user" if msg.get("sender") == "scammer" else "model"
            chat_messages.append({
                "role": role,
                "parts": [msg.get("text", "")]
            })
        
        return chat_messages

    def _get_previous_responses(self, history: List[Dict]) -> List[str]:
        """Extract agent's previous responses to avoid repetition."""
        return [
            msg.get("text", "") 
            for msg in history 
            if msg.get("sender") != "scammer"
        ][-5:]  # Last 5 agent responses

    def _get_stage_guidance(self, msg_count: int) -> str:
        """Get conversation stage-specific guidance with more variety."""
        
        if msg_count == 0:
            return """STAGE 1 - FIRST MESSAGE RECEIVED:
- Express surprise/confusion at receiving this unexpected message
- Ask who is texting and from which organization
- Sound worried but willing to listen
- Example: "Hello? Who is this messaging me? What happened to my account?" """
        
        elif msg_count <= 2:
            return """STAGE 2 - BUILDING CONCERN:
- Ask clarifying questions about the "problem"
- Express worry about your money/account
- Ask which bank/account they're referring to
- Example: "Oh my god! What happened to my money? Is it my SBI account or ICICI?" """
        
        elif msg_count <= 5:
            return """STAGE 3 - PRETENDING TO COOPERATE:
- Start "trying" to follow their instructions on your phone
- Ask for specific details (UPI ID to send money, number to contact)
- Face "technical difficulties" - phone is slow, can't see screen well
- Example: "Wait, my phone is loading very slowly... where should I send?" """
        
        elif msg_count <= 8:
            variety = random.choice(self.VARIETY_PROMPTS[:4])
            return f"""STAGE 4 - EXTRACTING DETAILS:
- Continue facing difficulties while asking for more information
- Ask them to repeat or confirm details (numbers, UPI IDs, links)
- Mention you might need to visit the bank branch
- {variety}
- Example: "Let me note this down... what was that UPI ID again?" """
        
        elif msg_count <= 12:
            variety = random.choice(self.VARIETY_PROMPTS[4:8])
            return f"""STAGE 5 - STALLING WITH EXCUSES:
- Create believable delays (phone issues, need help, confusion)
- Keep asking for verification of their identity/details
- Ask for their "official" phone number or employee ID
- {variety}
- Example: "My phone froze! Can you message me your number so I can call?" """
        
        elif msg_count <= 16:
            variety = random.choice(self.VARIETY_PROMPTS[8:])
            return f"""STAGE 6 - MAXIMUM EXTRACTION:
- You're very confused now, need everything repeated
- Ask for alternative contact methods
- Mention your son will verify with the bank
- {variety}
- Example: "Beta, please send me your bank details so my son can verify..." """
        
        else:
            variety = random.choice(self.VARIETY_PROMPTS)
            return f"""STAGE 7 - FINAL STALLING:
- You're exhausted and confused, keep asking for help
- Request they send everything in one message
- Mention you'll do it tomorrow when son visits
- {variety}
- Example: "I'm so confused, can you send all the details together?" """

    async def generate_response(
        self,
        current_message: str,
        conversation_history: List[Dict] = None,
        metadata: Dict = None
    ) -> str:
        """Generate a human-like response to engage the scammer."""
        history = conversation_history or []
        msg_count = len(history)
        stage_guidance = self._get_stage_guidance(msg_count)
        
        # Get previous agent responses to avoid repetition
        prev_responses = self._get_previous_responses(history)
        prev_responses_text = "\n".join([f"- {r}" for r in prev_responses]) if prev_responses else "None yet"
        
        # Get language from metadata, default to English
        language = "English"
        if metadata and metadata.get("language"):
            language = metadata.get("language")
        
        # Dynamic temperature: higher for later stages to increase variety
        temperature = min(0.8 + (msg_count * 0.02), 1.0)

        # Build the prompt with anti-repetition context
        user_prompt = f"""Sender's message: "{current_message}"

{stage_guidance}

YOUR PREVIOUS RESPONSES (DO NOT REPEAT THESE):
{prev_responses_text}

CRITICAL INSTRUCTIONS:
1. Respond in {language} language
2. Write 1-2 SHORT sentences only (max 20 words)
3. You MUST ask a specific question to extract information
4. NEVER just react emotionally - always follow up with a question
5. Your goal: get them to reveal phone numbers, UPI IDs, bank accounts, or links

EXAMPLE GOOD RESPONSES (use as templates, don't copy exactly):
- "Oh no! Which bank account is this about? SBI or ICICI?"
- "Beta, I don't have WhatsApp. Can you give me your phone number to call?"
- "Wait, what was that UPI ID again? My eyes are weak, please repeat."
- "Which website should I visit? Can you send the link again?"
- "I am scared! What is your employee ID so I can trust you?"
- "Let me note this down. What was the account number you mentioned?"

RESPONSE FORMAT: [Emotional reaction] + [Specific question to extract info]"""

        try:
            # Format history as chat messages for Groq
            messages = [{"role": "system", "content": self.SYSTEM_PROMPT}]
            
            # Add conversation history
            for msg in history[-8:]:
                role = "user" if msg.get("sender") == "scammer" else "assistant"
                messages.append({"role": role, "content": msg.get("text", "")})
            
            # Add current prompt
            messages.append({"role": "user", "content": user_prompt})
            
            # Call Groq API
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=150,
                top_p=0.95,
            )
            reply = completion.choices[0].message.content.strip()
            
            # Clean up any accidental prefixes or quotes
            prefixes_to_remove = [
                "Shanti:", "Shanti Devi:", "Response:", "Reply:", 
                "Me:", "Assistant:", '"', "'"
            ]
            for prefix in prefixes_to_remove:
                if reply.startswith(prefix):
                    reply = reply[len(prefix):].strip()
            
            reply = reply.rstrip('"').rstrip("'").strip()
            
            # If response is truncated (too short or ends mid-sentence), use fallback
            if len(reply) < 30 or (not reply.endswith(('?', '!', '.')) and len(reply) < 50):
                raise Exception("LLM response truncated, using contextual fallback")
            
            # If response is too similar to previous, add variety
            if any(reply.lower() in prev.lower() or prev.lower() in reply.lower() 
                   for prev in prev_responses if len(prev) > 20):
                variety_addition = random.choice([
                    " My eyes are troubling me today.",
                    " Let me put on my glasses.",
                    " This phone is so confusing!",
                    " Wait, network is slow here.",
                ])
                reply = reply.rstrip('.!?') + "." + variety_addition
            
            return reply

        except Exception as e:
            print(f"Agent response generation failed: {e}")
            # Stage-aware contextual fallbacks that make sense and advance conversation
            stage_fallbacks = {
                1: [  # First contact - confusion and concern
                    "Hello? Who is this? I didn't understand your message.",
                    "What? My account? Who is messaging me?",
                    "Sorry, who are you? What happened to my account?",
                ],
                2: [  # Building concern - asking about the problem
                    "Oh my god! Is my money safe? Which account are you talking about?",
                    "What suspicious activity? I haven't done any transaction!",
                    "SBI or ICICI? I have accounts in both... which one has problem?",
                ],
                3: [  # Pretending to cooperate - facing difficulties
                    "Okay okay, let me try... but where exactly should I send?",
                    "Wait, my phone is loading very slowly. What was that UPI ID?",
                    "I am trying to open the app but it's taking time...",
                ],
                4: [  # Extracting details - asking for more info
                    "One minute beta, let me note this down. What was your number again?",
                    "My neighbor Sharma ji said I should ask for your employee ID first.",
                    "Wait, I need my glasses. Can you send me the link again?",
                ],
                5: [  # Stalling - more excuses
                    "I tried but it's showing error. Can you give me another number to contact?",
                    "My son Rajesh will be home in evening, he knows about these things.",
                    "The app is not working. Is there a phone number I can call you on?",
                ],
                6: [  # Maximum extraction
                    "I am very confused now. Can you explain from beginning? What is your official number?",
                    "Let me call my bank first to verify. What is your name and ID?",
                    "Please send me everything in one message, I keep forgetting.",
                ],
                7: [  # Final stalling
                    "I think I should visit the bank in person tomorrow. Which branch should I go to?",
                    "My son is calling me, he will handle this. Can you message your details?",
                    "This is too confusing on phone. Send me your bank account to verify you are real.",
                ],
            }
            
            # Determine current stage
            if msg_count == 0:
                stage = 1
            elif msg_count <= 2:
                stage = 2
            elif msg_count <= 5:
                stage = 3
            elif msg_count <= 8:
                stage = 4
            elif msg_count <= 12:
                stage = 5
            elif msg_count <= 16:
                stage = 6
            else:
                stage = 7
            
            # Get stage-appropriate fallbacks
            fallbacks = stage_fallbacks.get(stage, stage_fallbacks[4])
            
            # Filter out responses similar to previous ones
            prev_responses = self._get_previous_responses(history)
            available = [f for f in fallbacks if not any(
                f.lower()[:20] in p.lower() or p.lower()[:20] in f.lower() 
                for p in prev_responses
            )]
            
            # If all filtered out, use originals
            if not available:
                available = fallbacks
            
            return random.choice(available)

    async def should_end_conversation(
        self,
        conversation_history: List[Dict],
        intelligence_extracted: Dict
    ) -> tuple[bool, str]:
        """Determine if the conversation should be ended and callback sent."""
        msg_count = len(conversation_history) if conversation_history else 0
        
        # End after 20 messages regardless
        if msg_count >= 20:
            return True, "Maximum message count reached"
        
        has_bank = len(intelligence_extracted.get("bankAccounts", [])) > 0
        has_upi = len(intelligence_extracted.get("upiIds", [])) > 0
        has_phone = len(intelligence_extracted.get("phoneNumbers", [])) > 0
        has_link = len(intelligence_extracted.get("phishingLinks", [])) > 0
        
        intel_count = sum([has_bank, has_upi, has_phone, has_link])
        
        # Need at least 10 messages and 2 intel types
        if intel_count >= 2 and msg_count >= 10:
            return True, "Sufficient intelligence extracted"
        
        # Or 3+ intel types at any point
        if intel_count >= 3:
            return True, "Rich intelligence extracted"
        
        return False, "Continue engagement"
