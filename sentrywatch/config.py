import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class SentrywatchConfig:
    db_path: Path = field(
        default_factory=lambda: Path(os.environ.get("SENTRYWATCH_DB", "sentrywatch.db"))
    )
    dry_run: bool = field(
        default_factory=lambda: os.environ.get("SENTRYWATCH_DRY_RUN", "true").lower() == "true"
    )
    anthropic_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY")
    )
    claude_model: str = field(
        default_factory=lambda: os.environ.get("SENTRYWATCH_MODEL", "claude-3-5-sonnet-20241022")
    )
    firewall_adapter: str = field(
        default_factory=lambda: os.environ.get("SENTRYWATCH_FIREWALL", "simulated")
    )
    default_ttl_seconds: int = 3600
    allowlist: List[str] = field(
        default_factory=lambda: [
            "127.0.0.1",
            "::1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    # Notification settings
    notify_enabled: bool = True
    notify_threshold: int = 70
    notify_channels: List[str] = field(
        default_factory=lambda: ["watch_terminal", "notify_send", "webhook"]
    )
    notify_webhook_url: Optional[str] = field(
        default_factory=lambda: os.environ.get("SENTRYWATCH_WEBHOOK_URL")
    )
    notify_cooldown_seconds: int = 300
    notify_scoring_down_alert_minutes: int = 10
    # Rule thresholds
    brute_force_threshold: int = 5
    brute_force_window: int = 120  # seconds
    port_scan_threshold: int = 10
    port_scan_window: int = 60  # seconds
    priv_esc_threshold: int = 3
    priv_esc_window: int = 300  # seconds
    anomalous_outbound_rarity_threshold: int = 1
    anomalous_outbound_window: int = 300  # seconds


_config_instance: Optional[SentrywatchConfig] = None


def load_env_file() -> None:
    env_path = Path(".env")
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("'\""))
        except Exception:
            pass


def get_config() -> SentrywatchConfig:
    global _config_instance
    if _config_instance is None:
        load_env_file()
        _config_instance = SentrywatchConfig()
    return _config_instance


def set_config(cfg: SentrywatchConfig) -> None:
    global _config_instance
    _config_instance = cfg
