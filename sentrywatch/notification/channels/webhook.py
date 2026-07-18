import logging
import requests
from typing import Optional
from sentrywatch.notification.channels.base import BaseNotificationChannel
from sentrywatch.notification.payload import NotificationPayload

logger = logging.getLogger("sentrywatch.notification.webhook")


class WebhookChannel(BaseNotificationChannel):
    def __init__(self, webhook_url: Optional[str] = None):
        super().__init__(name="webhook")
        self.webhook_url = webhook_url

    def send(self, payload: NotificationPayload) -> bool:
        if not self.webhook_url:
            logger.info(f"[Webhook omitted - no URL configured] Alert payload: {payload.to_dict()}")
            return True

        headers = {"Content-Type": "application/json"}
        # Generic payload format compatible with ntfy.sh, Discord, and custom webhooks
        data = {
            "title": f"Sentrywatch Alert: {payload.incident_type}",
            "message": f"IP: {payload.source_ip} | Reason: {payload.event_reason}",
            "payload": payload.to_dict(),
            "content": f"🛡️ **Sentrywatch Alert**: `{payload.incident_type}` from `{payload.source_ip}`\n"
                       f"• **Severity Score**: {payload.severity_score}\n"
                       f"• **Recommended Action**: {payload.recommended_action}\n"
                       f"• **Enforcement**: {payload.enforcement_status}\n"
                       f"• **Reason**: {payload.event_reason}",
        }

        try:
            resp = requests.post(self.webhook_url, json=data, headers=headers, timeout=5.0)
            return resp.status_code in [200, 201, 202, 204]
        except Exception as e:
            logger.error(f"Webhook dispatch failed to {self.webhook_url}: {e}")
            return False
