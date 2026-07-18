from rich.console import Console
from rich.panel import Panel
from sentrywatch.notification.channels.base import BaseNotificationChannel
from sentrywatch.notification.payload import NotificationPayload


class TerminalWatchChannel(BaseNotificationChannel):
    def __init__(self, console: Console = None):
        super().__init__(name="watch_terminal")
        self.console = console or Console()

    def send(self, payload: NotificationPayload) -> bool:
        style = "bold red" if payload.enforcement_status == "enforced" else "bold yellow"
        border_style = "red" if payload.enforcement_status == "enforced" else "yellow"

        body = (
            f"[{style}][ALERT] INCIDENT: {payload.incident_type}[/{style}]\n"
            f"Source IP:          {payload.source_ip}\n"
            f"Severity Score:     {payload.severity_score if payload.severity_score is not None else 'N/A'}/100\n"
            f"Recommended Action: {payload.recommended_action or 'N/A'}\n"
            f"Enforcement Status: {payload.enforcement_status}\n"
            f"Trigger Reason:     {payload.event_reason}\n"
            f"Lookup Ref:         {payload.lookup_reference}"
        )

        self.console.print(Panel(body, title="Sentrywatch Notification", border_style=border_style))
        return True
