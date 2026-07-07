"""
SOC AI Assistant — Chat Service

Handles context-aware chat conversation with security analysts.
Injects current alert context, MITRE definitions, and prior history to ground response.
"""

from sqlalchemy.orm import Session
from backend.models import ChatMessage, Alert
from backend.services.ai.client import call_ai
from backend.services.ai.prompts import CHAT_SYSTEM
from typing import Optional
import json


def get_chat_history(db: Session, session_id: str, limit: int = 20) -> list[ChatMessage]:
    """Retrieve chat message history for a session."""
    return db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.timestamp.asc()).limit(limit).all()


def clear_chat_history(db: Session, session_id: str):
    """Clear chat message history for a session."""
    db.query(ChatMessage).filter(ChatMessage.session_id == session_id).delete()
    db.commit()


async def process_chat_message(db: Session, session_id: str, user_message: str, alert_id: int = None) -> str:
    """
    Processes chat requests with context-aware grounding.
    If alert_id is provided, loads the alert detail and injects it into prompt context.
    """
    # 1. Build Context
    context_data = ""
    context_json = {}
    
    if alert_id:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            context_json["alert_id"] = alert_id
            context_json["alert_description"] = alert.description
            context_json["alert_host"] = alert.host
            
            context_data += (
                f"CURRENTLY VIEWED ALERT DETAILS:\n"
                f"- Alert ID: {alert.id}\n"
                f"- Timestamp: {alert.timestamp}\n"
                f"- Host: {alert.host}\n"
                f"- Source IP: {alert.source_ip}\n"
                f"- Destination IP: {alert.dest_ip}\n"
                f"- Event ID: {alert.event_id}\n"
                f"- MITRE Tactic: {alert.mitre_tactic}\n"
                f"- MITRE Technique: {alert.mitre_technique_id} ({alert.mitre_technique_name})\n"
                f"- Raw Log:\n{alert.raw_log}\n\n"
            )
            
            # Find related alerts on the same host
            related_alerts = db.query(Alert).filter(
                Alert.host == alert.host,
                Alert.id != alert.id
            ).order_by(Alert.timestamp.desc()).limit(5).all()
            
            if related_alerts:
                context_data += "RELATED ALERTS ON SAME HOST:\n"
                for ra in related_alerts:
                    context_data += f"- {ra.timestamp}: {ra.description} (Severity: {ra.severity}, MITRE: {ra.mitre_technique_id})\n"
                context_data += "\n"

    # Load recent conversation history (last 6 messages for token efficiency)
    history = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.timestamp.desc()).limit(6).all()
    history = list(reversed(history))

    # Format prompt system instructions
    system_prompt = CHAT_SYSTEM.format(context=context_data or "No specific alert context loaded.")

    # 2. Build OpenRouter messages list
    messages = []
    # For call_ai helper, we supply system and user prompts. To support multi-turn history,
    # we can construct a unified user prompt incorporating history, or directly use the OpenAI client if we want multi-turn.
    # Let's import the OpenAI SDK client directly to handle multi-turn message lists properly!
    from backend.services.ai.client import get_client, get_model, get_temperature, get_max_tokens
    
    openai_client = get_client()
    
    if openai_client is None:
        # Fallback to a mock chat response
        ai_response = _get_mock_chat_response(user_message, alert_id)
    else:
        # Construct message payload with history
        payload = [{"role": "system", "content": system_prompt}]
        for h in history:
            payload.append({"role": h.role, "content": h.content})
        payload.append({"role": "user", "content": user_message})
        
        try:
            response = await openai_client.chat.completions.create(
                model=get_model(),
                messages=payload,
                temperature=get_temperature(),
                max_tokens=get_max_tokens(),
            )
            ai_response = response.choices[0].message.content
        except Exception as e:
            ai_response = f"Error communicating with AI: {str(e)}"

    # Save to history
    user_msg = ChatMessage(session_id=session_id, role="user", content=user_message, context_json=context_json)
    assistant_msg = ChatMessage(session_id=session_id, role="assistant", content=ai_response, context_json=None)
    db.add(user_msg)
    db.add(assistant_msg)
    db.commit()

    return ai_response


def _get_mock_chat_response(msg: str, alert_id: Optional[int]) -> str:
    """Produces mock chatbot replies based on query patterns."""
    msg = msg.lower()
    
    if "4625" in msg:
        return ("**Event ID 4625** represents a **Failed User Logon** on Windows systems.\n\n"
                "### Investigation Steps:\n"
                "1. Identify the targeted account (e.g. administrator).\n"
                "2. Check the LogonType (Type 10 is RDP, Type 3 is Network share).\n"
                "3. Source IP analysis (look for external or internal brute-forcing hosts).\n"
                "4. Check for subsequent Event ID 4624 (Success) from the same source IP.")
                
    if "powershell" in msg or "t1059" in msg:
        return ("**MITRE ATT&CK T1059 (Command and Scripting Interpreter)** is used by attackers to execute commands.\n\n"
                "In Windows environments, this often involves **PowerShell** (T1059.001) or CMD (T1059.003).\n\n"
                "### Key Detection Elements:\n"
                "- Spawning of shell processes by Office documents or web servers.\n"
                "- Encoded command execution (`-EncodedCommand` or `-e`).\n"
                "- Script execution bypass switches (`-ExecutionPolicy Bypass`).")
                
    if alert_id:
        return (f"Regarding the currently loaded alert (ID: {alert_id}):\n\n"
                "This behavior looks highly suspicious. To investigate further:\n"
                "- Pivot to the alerts list and filter by the source IP address.\n"
                "- Look up this IP in the Threat Intel panel to see if it is classified as known malicious.\n"
                "- Gather host telemetry or trigger an endpoint isolation action.")

    return ("I am in offline mode because no valid OpenRouter API key has been configured in Settings.\n\n"
            "Here is some general advice:\n"
            "- Check the logs for unusual user-agent strings, file hashes, or external connections.\n"
            "- Correlate authentication logs with firewall rules.")
