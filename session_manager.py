"""Session management for tracking conversations."""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from models import MessageInput, ExtractedIntelligence


@dataclass
class SessionState:
    """State for a single conversation session."""
    session_id: str
    scam_detected: bool = False
    scam_confidence: float = 0.0
    messages: List[Dict] = field(default_factory=list)
    extracted_intelligence: ExtractedIntelligence = field(
        default_factory=ExtractedIntelligence
    )
    agent_notes: str = ""
    callback_sent: bool = False

    @property
    def total_messages(self) -> int:
        return len(self.messages)


class SessionManager:
    """In-memory session store for conversation tracking."""

    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

    def get_or_create(self, session_id: str) -> SessionState:
        """Get existing session or create a new one."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def get(self, session_id: str) -> Optional[SessionState]:
        """Get session by ID, returns None if not found."""
        return self._sessions.get(session_id)

    def add_message(self, session_id: str, sender: str, text: str, timestamp: int):
        """Add a message to the session history."""
        session = self.get_or_create(session_id)
        session.messages.append({
            "sender": sender,
            "text": text,
            "timestamp": timestamp
        })

    def mark_scam_detected(self, session_id: str, confidence: float):
        """Mark session as having detected scam intent."""
        session = self.get_or_create(session_id)
        session.scam_detected = True
        session.scam_confidence = confidence

    def update_intelligence(
        self,
        session_id: str,
        intelligence: ExtractedIntelligence
    ):
        """Update extracted intelligence for a session."""
        session = self.get_or_create(session_id)
        # Merge new intelligence with existing
        session.extracted_intelligence.bankAccounts = list(set(
            session.extracted_intelligence.bankAccounts + intelligence.bankAccounts
        ))
        session.extracted_intelligence.upiIds = list(set(
            session.extracted_intelligence.upiIds + intelligence.upiIds
        ))
        session.extracted_intelligence.phishingLinks = list(set(
            session.extracted_intelligence.phishingLinks + intelligence.phishingLinks
        ))
        session.extracted_intelligence.phoneNumbers = list(set(
            session.extracted_intelligence.phoneNumbers + intelligence.phoneNumbers
        ))
        session.extracted_intelligence.suspiciousKeywords = list(set(
            session.extracted_intelligence.suspiciousKeywords + intelligence.suspiciousKeywords
        ))

    def set_agent_notes(self, session_id: str, notes: str):
        """Set agent notes for a session."""
        session = self.get_or_create(session_id)
        session.agent_notes = notes

    def mark_callback_sent(self, session_id: str):
        """Mark that the GUVI callback has been sent."""
        session = self.get_or_create(session_id)
        session.callback_sent = True

    def delete(self, session_id: str):
        """Delete a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]


# Global session manager instance
session_manager = SessionManager()
