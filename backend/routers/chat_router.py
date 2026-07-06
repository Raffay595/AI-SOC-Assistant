"""
SOC AI Assistant — Chat Assistant Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.schemas import ChatRequest, ChatResponse, ChatHistoryItem
from backend.services.chat import service as chat_service

router = APIRouter(prefix="/api/chat", tags=["AI Chat Assistant"])


@router.post("", response_model=ChatResponse)
async def send_message(req: ChatRequest, db: Session = Depends(get_db)):
    """Sends conversational message to security agent with optional alert context."""
    try:
        reply = await chat_service.process_chat_message(
            db=db,
            session_id=req.session_id,
            user_message=req.message,
            alert_id=req.alert_id
        )
        return ChatResponse(
            response=reply,
            session_id=req.session_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")


@router.get("/history/{session_id}", response_model=list[ChatHistoryItem])
def get_chat_session_history(session_id: str, db: Session = Depends(get_db)):
    """Retrieve history of conversation in a session."""
    return chat_service.get_chat_history(db, session_id)


@router.delete("/history/{session_id}")
def clear_chat_session_history(session_id: str, db: Session = Depends(get_db)):
    """Clear chat conversation log for a session ID."""
    chat_service.clear_chat_history(db, session_id)
    return {"status": "history cleared"}
