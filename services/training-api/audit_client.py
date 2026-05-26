import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

REVIEW_API_URL = os.getenv("REVIEW_API_URL", "http://review-api:8082")


async def log_audit(
    action: str,
    outcome: str,
    details: Optional[dict] = None,
    user_id: str = "system",
    user_email: str = "training-api@modintel.local",
    role: str = "system",
):
    try:
        import httpx

        payload = {
            "action": action,
            "outcome": outcome,
            "user_id": user_id,
            "user_email": user_email,
            "role": role,
            "details": details or {},
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{REVIEW_API_URL}/api/admin/audit/log", json=payload
            )
            if resp.status_code == 200:
                logger.info(f"Audit event logged: {action} ({outcome})")
            else:
                logger.warning(
                    f"Failed to log audit event: {resp.status_code} {resp.text}"
                )
    except Exception as e:
        logger.error(f"Error logging audit event: {e}")
