from abc import ABC, abstractmethod
from sentrywatch.notification.payload import NotificationPayload


class BaseNotificationChannel(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def send(self, payload: NotificationPayload) -> bool:
        """Send notification payload. Returns True on success, False on failure."""
        pass
