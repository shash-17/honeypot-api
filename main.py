"""
Agentic Honey-Pot API for Scam Detection & Intelligence Extraction.

This FastAPI application provides an endpoint to:
1. Detect scam messages
2. Engage scammers with an AI agent
3. Extract intelligence (bank accounts, UPI IDs, phone numbers, links)
4. Send final results to GUVI evaluation endpoint
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from models import AnalyzeRequest, AnalyzeResponse, ExtractedIntelligence
from session_manager import session_manager
from scam_detector import ScamDetector
from agent import HoneypotAgent
from intelligence_extractor import IntelligenceExtractor
from guvi_callback import send_final_result

# Load environment variables
load_dotenv()

# Global instances
scam_detector: Optional[ScamDetector] = None
honeypot_agent: Optional[HoneypotAgent] = None
intel_extractor: Optional[IntelligenceExtractor] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize components on startup."""
    global scam_detector, honeypot_agent, intel_extractor
    
    # Use GROQ_API_KEY
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY environment variable not set")
    
    scam_detector = ScamDetector(api_key)
    honeypot_agent = HoneypotAgent(api_key)
    intel_extractor = IntelligenceExtractor(api_key)
    
    print("🍯 Agentic Honey-Pot API initialized successfully (Groq LLM)")
    yield
    print("🍯 Agentic Honey-Pot API shutting down")


# Initialize FastAPI app
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def verify_api_key(x_api_key: str = Header(...)):
    """Verify the API key from request headers."""
    expected_key = os.getenv("API_SECRET_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=500,
            detail="API_SECRET_KEY not configured on server"
        )
    if x_api_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key


@app.get("/")
async def root():
    """Root endpoint for health check."""
    return {
        "status": "running",
        "service": "Agentic Honey-Pot API",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_message(
    request: AnalyzeRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Analyze an incoming message for scam intent and respond.
    
    This endpoint:
    1. Receives a message from the evaluation platform
    2. Detects if the message is a scam
    3. If scam detected, activates the AI agent
    4. Extracts intelligence from the conversation
    5. Returns a human-like response
    6. Sends final results to GUVI when conversation completes
    """
    session_id = request.sessionId
    message = request.message
    history = request.conversationHistory
    metadata = request.metadata

    # Bug 6 fix: Validate session_id
    if not session_id or not session_id.strip():
        raise HTTPException(
            status_code=400,
            detail="sessionId is required and cannot be empty"
        )

    # Validate message text
    if not message.text or not message.text.strip():
        raise HTTPException(
            status_code=400,
            detail="message.text is required and cannot be empty"
        )

    # Get or create session
    session = session_manager.get_or_create(session_id)

    # Build full conversation history
    full_history = [
        {"sender": msg.sender, "text": msg.text, "timestamp": msg.timestamp}
        for msg in history
    ]
    
    # Add current message to history
    session_manager.add_message(
        session_id,
        message.sender,
        message.text,
        message.timestamp
    )
    full_history.append({
        "sender": message.sender,
        "text": message.text,
        "timestamp": message.timestamp
    })

    # Detect scam intent (on first message or if not yet detected)
    if not session.scam_detected:
        detection_result = await scam_detector.detect(
            message.text,
            full_history
        )
        
        if detection_result["is_scam"]:
            session_manager.mark_scam_detected(
                session_id,
                detection_result["confidence"]
            )

    # Extract intelligence from all messages
    intelligence = intel_extractor.extract_all(full_history)
    session_manager.update_intelligence(session_id, intelligence)

    # Generate agent response
    agent_reply = await honeypot_agent.generate_response(
        current_message=message.text,
        conversation_history=full_history,
        metadata=metadata.model_dump() if metadata else None
    )

    # Add agent's response to session
    import time
    session_manager.add_message(
        session_id,
        "user",
        agent_reply,
        int(time.time() * 1000)
    )

    # Check if conversation should end
    session = session_manager.get(session_id)
    should_end, end_reason = await honeypot_agent.should_end_conversation(
        session.messages,
        session.extracted_intelligence.model_dump()
    )

    # Send callback if conversation should end and we detected a scam
    if should_end and session.scam_detected and not session.callback_sent:
        # Generate agent notes with extracted intelligence
        agent_notes = await intel_extractor.generate_agent_notes(
            session.messages, 
            session.extracted_intelligence
        )
        session_manager.set_agent_notes(session_id, agent_notes)
        
        # Send to GUVI
        callback_result = await send_final_result(
            session_id=session_id,
            scam_detected=session.scam_detected,
            total_messages=session.total_messages,
            intelligence=session.extracted_intelligence,
            agent_notes=agent_notes
        )
        
        if callback_result["success"]:
            session_manager.mark_callback_sent(session_id)
            print(f"✅ Callback sent for session {session_id}")
        else:
            print(f"❌ Callback failed for session {session_id}: {callback_result}")

    # Calculate conversation stage for metrics
    msg_count = session.total_messages
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

    # Return complete response with all metrics for evaluation
    print(f"DEBUG: Final Intelligence for session {session_id}: {session.extracted_intelligence.model_dump()}")
    return AnalyzeResponse(
        status="success",
        reply=agent_reply,
        sessionId=session_id,
        scamDetected=session.scam_detected,
        extractedIntelligence=session.extracted_intelligence,
        totalMessagesExchanged=session.total_messages,
        conversationStage=stage
    )


@app.get("/session/{session_id}")
async def get_session_info(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get information about a specific session (for debugging)."""
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_confidence": session.scam_confidence,
        "total_messages": session.total_messages,
        "callback_sent": session.callback_sent,
        "extracted_intelligence": session.extracted_intelligence.model_dump(),
        "agent_notes": session.agent_notes
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
