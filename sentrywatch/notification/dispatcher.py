import logging
import queue
import threading
import time
from typing import Dict, List, Optional
from sentrywatch.audit.logger import AuditLogger
from sentrywatch.config import SentrywatchConfig
from sentrywatch.notification.channels.base import BaseNotificationChannel
from sentrywatch.notification.channels.notify_send import NotifySendChannel
from sentrywatch.notification.channels.terminal import TerminalWatchChannel
from sentrywatch.notification.channels.webhook import WebhookChannel
from sentrywatch.notification.payload import NotificationPayload

logger = logging.getLogger("sentrywatch.notification.dispatcher")


class NotificationDispatcher:
    def __init__(self, config: SentrywatchConfig, audit_logger: Optional[AuditLogger] = None):
        self.config = config
        self.audit_logger = audit_logger
        self.queue: queue.Queue = queue.Queue()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Build channels registry
        self.channels: Dict[str, BaseNotificationChannel] = {
            "notify_send": NotifySendChannel(),
            "webhook": WebhookChannel(webhook_url=config.notify_webhook_url),
            "watch_terminal": TerminalWatchChannel(),
        }

    def start(self) -> None:
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        self._running = False
        self.queue.put(None)  # Sentinel
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

    def dispatch_async(self, payload: NotificationPayload) -> None:
        """Enqueue payload for async non-blocking dispatch."""
        if not self.config.notify_enabled:
            return
        self.queue.put(payload)

    def _worker_loop(self) -> None:
        while self._running:
            try:
                payload: Optional[NotificationPayload] = self.queue.get(timeout=1.0)
                if payload is None:
                    break
                self._send_payload(payload)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in notification worker loop: {e}")

    def _send_payload(self, payload: NotificationPayload) -> None:
        active_channel_names = self.config.notify_channels
        for name in active_channel_names:
            ch = self.channels.get(name)
            if not ch:
                continue

            success = False
            attempts = 0
            max_attempts = 3

            while attempts < max_attempts and not success:
                attempts += 1
                try:
                    success = ch.send(payload)
                except Exception as e:
                    logger.error(f"Channel {name} exception on attempt {attempts}: {e}")
                    success = False

                status = "sent" if success else ("retrying" if attempts < max_attempts else "failed")

                if self.audit_logger:
                    self.audit_logger.log_event(
                        "notification",
                        {
                            "incident_id": payload.incident_id,
                            "channel": name,
                            "attempt": attempts,
                            "status": status,
                            "source_ip": payload.source_ip,
                            "reason": payload.event_reason,
                        },
                    )

                if not success and attempts < max_attempts:
                    time.sleep(0.5)
