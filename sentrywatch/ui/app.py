import sys
import time
from typing import Optional
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Repository
from sentrywatch.ui.views import UIViewRenderer


class SentrywatchTUI:
    def __init__(self, repo: Repository, config: SentrywatchConfig):
        self.repo = repo
        self.config = config
        self.console = Console()
        self.renderer = UIViewRenderer(repo, config)
        self.active_tab = "1"  # 1: Dashboard, 2: Detail, 3: IP Browser, 4: Audit, 5: Config
        self.running = False

    def build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
        )

        layout["header"].update(self.renderer.render_header(self.active_tab))

        if self.active_tab == "1":
            layout["main"].update(self.renderer.render_dashboard())
        elif self.active_tab == "2":
            layout["main"].update(self.renderer.render_incident_detail())
        elif self.active_tab == "3":
            layout["main"].update(self.renderer.render_ip_reputation_browser())
        elif self.active_tab == "4":
            layout["main"].update(self.renderer.render_audit_log_viewer())
        elif self.active_tab == "5":
            layout["main"].update(self.renderer.render_config_view())

        return layout

    def run(self, refresh_rate: float = 1.0) -> None:
        self.running = True
        with Live(
            self.build_layout(),
            console=self.console,
            refresh_per_second=2,
            screen=True,
        ) as live:
            try:
                while self.running:
                    live.update(self.build_layout())
                    time.sleep(refresh_rate)
            except KeyboardInterrupt:
                self.running = False
