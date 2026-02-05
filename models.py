"""Pydantic models for request/response validation."""

from typing import List, Optional
from pydantic import BaseModel, Field


class MessageInput(BaseModel):
    """Incoming message structure."""
    sender: str = Field(..., description="Either 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: int = Field(..., description="Epoch time in milliseconds")


class Metadata(BaseModel):
    """Optional metadata about the conversation."""
    channel: Optional[str] = Field(None, description="SMS / WhatsApp / Email / Chat")
    language: Optional[str] = Field("English", description="Language used")
    locale: Optional[str] = Field("IN", description="Country or region")


class AnalyzeRequest(BaseModel):
    """Full request body for /analyze endpoint."""
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessageInput = Field(..., description="Latest incoming message")
    conversationHistory: List[MessageInput] = Field(
        default_factory=list,
        description="Previous messages in the conversation"
    )
    metadata: Optional[Metadata] = Field(default_factory=Metadata)


class AnalyzeResponse(BaseModel):
    """Response from /analyze endpoint."""
    status: str = Field(..., description="'success' or 'error'")
    reply: str = Field(..., description="Agent's response message")
    sessionId: Optional[str] = Field(None, description="Session identifier for tracking")
    scamDetected: Optional[bool] = Field(None, description="Whether scam was detected")
    extractedIntelligence: Optional["ExtractedIntelligence"] = Field(
        None, description="Intelligence extracted so far"
    )
    # Engagement metrics for evaluation
    totalMessagesExchanged: Optional[int] = Field(None, description="Total messages in session")
    conversationStage: Optional[int] = Field(None, description="Current conversation stage (1-7)")


class ExtractedIntelligence(BaseModel):
    """Intelligence extracted from scam conversation."""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class GUVICallbackPayload(BaseModel):
    """Payload for GUVI final result callback."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
