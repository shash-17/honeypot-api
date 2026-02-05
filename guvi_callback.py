"""GUVI callback for sending final results."""

import httpx
from models import GUVICallbackPayload, ExtractedIntelligence

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


async def send_final_result(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    intelligence: ExtractedIntelligence,
    agent_notes: str
) -> dict:
    """
    Send final extracted intelligence to GUVI evaluation endpoint.
    
    Args:
        session_id: Unique session ID from the platform
        scam_detected: Whether scam intent was confirmed
        total_messages: Total messages exchanged in the session
        intelligence: Extracted intelligence data
        agent_notes: Summary of scammer behavior
        
    Returns:
        Response from GUVI endpoint or error details
    """
    payload = GUVICallbackPayload(
        sessionId=session_id,
        scamDetected=scam_detected,
        totalMessagesExchanged=total_messages,
        extractedIntelligence=intelligence,
        agentNotes=agent_notes
    )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GUVI_CALLBACK_URL,
                json=payload.model_dump(),
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            return {
                "success": response.status_code == 200,
                "status_code": response.status_code,
                "response": response.json() if response.status_code == 200 else response.text
            }
            
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "Request timed out",
            "status_code": None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "status_code": None
        }
