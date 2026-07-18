import logging
import shutil
import subprocess
from sentrywatch.notification.channels.base import BaseNotificationChannel
from sentrywatch.notification.payload import NotificationPayload

logger = logging.getLogger("sentrywatch.notification.notify_send")


class NotifySendChannel(BaseNotificationChannel):
    def __init__(self):
        super().__init__(name="notify_send")

    def send(self, payload: NotificationPayload) -> bool:
        title = f"[Sentrywatch Alert] {payload.incident_type}"
        message = (
            f"Source IP: {payload.source_ip}\n"
            f"Severity: {payload.severity_score or 'N/A'} | Action: {payload.recommended_action or 'N/A'}\n"
            f"Reason: {payload.event_reason}"
        )

        notify_send_path = shutil.which("notify-send")
        if not notify_send_path:
            logger.info(f"[notify-send mock fallback] {title}: {message}")
            return True

        try:
            cmd = [
                notify_send_path,
                "-u",
                "critical" if payload.enforcement_status == "enforced" else "normal",
                "-a",
                "Sentrywatch",
                title,
                message,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to execute notify-send: {e}")
            return False
