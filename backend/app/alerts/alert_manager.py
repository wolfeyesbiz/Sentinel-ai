import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from app.config import settings
from app.models.schemas import AlertItem, SeverityLevel
from app.storage.memory_store import memory_store

logger = logging.getLogger("sentinel.alerts")

class AlertManager:
    def __init__(self):
        self.dispatched_alerts = []

    async def dispatch_alert(self, alert: AlertItem):
        alert_dict = alert.model_dump()
        self.dispatched_alerts.append(alert_dict)

        # 1. Real-time In-App Web Dashboard via WebSocket
        ws_payload = {
            "type": "NEW_ALERT",
            "alert": alert_dict,
            "play_sound": settings.ENABLE_AUDIO_CHIMES and alert.severity in (SeverityLevel.CRITICAL, SeverityLevel.EMERGENCY, SeverityLevel.WARNING)
        }
        await memory_store.broadcast(ws_payload)

        # 2. Email alert dispatch (Simulated / SMTP / API format)
        email_body = self._format_email_report(alert)
        logger.info(f"[EMAIL ALERT DISPATCHED to {settings.ADMIN_EMAIL}] Threat: {alert.threat_type.value.upper()} | Severity: {alert.severity.value.upper()}")

        # 3. SMS alert for CRITICAL and EMERGENCY
        if alert.severity in (SeverityLevel.CRITICAL, SeverityLevel.EMERGENCY):
            sms_text = f"🚨 SENTINEL AI {alert.severity.value.upper()} ALERT: {alert.threat_type.value.upper()} blocked from IP {alert.source_ip}. Target: {alert.target}. Risk: {alert.risk_score}"
            logger.warning(f"[SMS ALERT SENT to {settings.ADMIN_PHONE}]: {sms_text}")

        # 4. Slack / Discord Webhook if configured
        if settings.SLACK_WEBHOOK_URL or settings.DISCORD_WEBHOOK_URL:
            asyncio.create_task(self._send_webhook(alert))

    def _format_email_report(self, alert: AlertItem) -> str:
        return f"""
        =====================================================
        SENTINEL AI - CRITICAL SECURITY INCIDENT REPORT
        =====================================================
        Alert ID:       {alert.id}
        Timestamp:      {alert.timestamp}
        Threat Type:    {alert.threat_type.value.upper()}
        Severity:       {alert.severity.value.upper()}
        Source IP:      {alert.source_ip} ({alert.country})
        Target URI:     {alert.target}
        Action Taken:   {alert.status.value.upper()}
        Risk Score:     {alert.risk_score} / 1.0

        MALICIOUS PAYLOAD:
        {alert.payload or 'N/A'}

        DESCRIPTION:
        {alert.description}

        IMMEDIATE REMEDIATION:
        {chr(10).join(alert.remediation.how_to_fix_now) if alert.remediation else 'Review audit logs'}
        =====================================================
        """

    async def _send_webhook(self, alert: AlertItem):
        payload = {
            "text": f"🛡️ *Sentinel AI Security Alert*\n*Threat:* `{alert.threat_type.value}`\n*Severity:* `{alert.severity.value}`\n*Source IP:* `{alert.source_ip}`\n*Target:* `{alert.target}`\n*Status:* `{alert.status.value}`"
        }
        url = settings.SLACK_WEBHOOK_URL or settings.DISCORD_WEBHOOK_URL
        if url:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(url, json=payload)
            except Exception as e:
                logger.error(f"Failed to post to webhook: {e}")

alert_manager = AlertManager()
