import datetime
from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from sentrywatch.audit.verifier import AuditVerifier
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Repository


class UIViewRenderer:
    def __init__(self, repo: Repository, config: SentrywatchConfig):
        self.repo = repo
        self.config = config
        self.start_time = datetime.datetime.now()

    def render_header(self, active_tab: str = "1") -> Panel:
        mode_text = "[bold yellow]MODE: DRY-RUN[/bold yellow]" if self.config.dry_run else "[bold red]MODE: ENFORCING[/bold red]"
        
        uptime_sec = int((datetime.datetime.now() - self.start_time).total_seconds())
        uptime_str = f"{uptime_sec // 3600:02d}:{(uptime_sec % 3600) // 60:02d}:{uptime_sec % 60:02d}"

        inc_1h = self.repo.count_incidents_since(3600)
        inc_24h = self.repo.count_incidents_since(86400)

        ai_status = "[bold green]OK[/bold green]" if self.config.anthropic_api_key else "[yellow]OFFLINE (Heuristic Fallback)[/yellow]"

        tabs_text = f"[1:Dashboard] [2:Incident Details] [3:IP Reputation] [4:Audit Log] [5:Rules & Config]"
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_column(justify="right")

        title = f"[bold white]🛡️ SENTRYWATCH v2.0[/bold white] | {mode_text} | Uptime: {uptime_str} | 1h Incidents: {inc_1h} | 24h: {inc_24h} | AI: {ai_status}"
        grid.add_row(title, f"[dim]{tabs_text}[/dim]")
        return Panel(grid, style="bold cyan")

    def render_dashboard(self) -> Layout:
        layout = Layout()
        layout.split_row(
            Layout(name="feed", ratio=3),
            Layout(name="top_ips", ratio=1),
        )

        # Main Incident Feed Table
        feed_table = Table(title="Live Incident Stream", expand=True, border_style="dim white")
        feed_table.add_column("Time", style="cyan", no_wrap=True)
        feed_table.add_column("Type", style="bold yellow")
        feed_table.add_column("Source IP", style="magenta")
        feed_table.add_column("Score", style="bold red", justify="center")
        feed_table.add_column("Action", style="green")
        feed_table.add_column("Status", style="blue")

        incidents = self.repo.list_incidents(limit=20)
        for inc in incidents:
            score_display = str(inc.severity_score) if inc.severity_score is not None else "-"
            score_style = "bold red" if inc.severity_score and inc.severity_score >= 75 else "bold yellow" if inc.severity_score and inc.severity_score >= 45 else "green"
            
            feed_table.add_row(
                inc.created_at[11:19] if len(inc.created_at) >= 19 else inc.created_at,
                inc.incident_type,
                inc.source_ip or "0.0.0.0",
                f"[{score_style}]{score_display}[/{score_style}]",
                inc.recommended_action or "review",
                inc.status,
            )

        layout["feed"].update(Panel(feed_table, title="[bold white]Incidents[/bold white]", border_style="cyan"))

        # Top IPs Side Pane
        ip_table = Table(title="Worst IP Reputation", expand=True, border_style="dim white")
        ip_table.add_column("IP", style="magenta")
        ip_table.add_column("Rep", style="bold red", justify="center")
        ip_table.add_column("Blocked", style="bold red")

        top_ips = self.repo.list_top_reputation_ips(limit=10)
        for rep in top_ips:
            blk_str = "[red]YES[/red]" if rep.currently_blocked else "[green]NO[/green]"
            ip_table.add_row(rep.ip, str(rep.reputation_score), blk_str)

        layout["top_ips"].update(Panel(ip_table, title="[bold white]Top Threat IPs[/bold white]", border_style="magenta"))
        return layout

    def render_incident_detail(self, incident_id: str = None) -> Panel:
        incidents = self.repo.list_incidents(limit=1)
        inc = self.repo.get_incident(incident_id) if incident_id else (incidents[0] if incidents else None)
        
        if not inc:
            return Panel("[dim]No incidents logged yet.[/dim]", title="Incident Inspector")

        rep = self.repo.get_ip_reputation(inc.source_ip) if inc.source_ip else None
        rep_score = rep.reputation_score if rep else 0
        rep_counts = str(rep.incident_counts) if rep else "N/A"

        body = Text()
        body.append(f"Incident ID: {inc.id}\n", style="bold white")
        body.append(f"Timestamp:   {inc.created_at}\n", style="cyan")
        body.append(f"Type:        {inc.incident_type}\n", style="bold yellow")
        body.append(f"Source IP:   {inc.source_ip or 'N/A'} (Reputation Score: {rep_score})\n", style="magenta")
        body.append(f"IP Counts:   {rep_counts}\n", style="dim")
        body.append(f"Rule Fired:  {inc.matched_rule_id or 'None'}\n", style="blue")
        body.append(f"Status:      {inc.status}\n\n", style="green")

        body.append("--- AI Advisory Assessment ---\n", style="bold magenta")
        body.append(f"Severity Score:     {inc.severity_score or 'N/A'}/100\n", style="bold red")
        body.append(f"Recommended Action: {inc.recommended_action or 'N/A'}\n", style="bold green")
        body.append(f"Confidence:         {inc.score_confidence or 'N/A'}\n", style="cyan")
        body.append(f"Rationale:          {inc.score_rationale or 'N/A'}\n\n", style="white")

        body.append("--- Raw Log Evidence ---\n", style="bold yellow")
        body.append(f"{inc.raw_evidence}\n", style="dim white")

        return Panel(body, title=f"[bold white]Incident Inspector - {inc.id[:8]}[/bold white]", border_style="yellow")

    def render_ip_reputation_browser(self) -> Panel:
        table = Table(expand=True, border_style="magenta")
        table.add_column("IP Address", style="bold magenta")
        table.add_column("First Seen", style="dim")
        table.add_column("Last Seen", style="cyan")
        table.add_column("Incident Counts", style="white")
        table.add_column("Rep Score", style="bold red", justify="center")
        table.add_column("Currently Blocked", style="bold yellow", justify="center")

        all_ips = self.repo.list_all_reputation_ips()
        for rep in all_ips:
            blk = "[bold red]BLOCKED[/bold red]" if rep.currently_blocked else "[green]ACTIVE[/green]"
            counts_summary = ", ".join([f"{k}:{v}" for k, v in rep.incident_counts.items()])
            table.add_row(
                rep.ip,
                rep.first_seen[11:19] if len(rep.first_seen) >= 19 else rep.first_seen,
                rep.last_seen[11:19] if len(rep.last_seen) >= 19 else rep.last_seen,
                counts_summary,
                str(rep.reputation_score),
                blk,
            )

        return Panel(table, title="[bold white]IP Threat Reputation Register[/bold white]", border_style="magenta")

    def render_audit_log_viewer(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="banner", size=3),
            Layout(name="table", ratio=1),
        )

        verifier = AuditVerifier(self.repo)
        res = verifier.verify_chain()

        if res.is_valid:
            banner = Panel(
                f"[bold green]✓ AUDIT LOG INTEGRITY VERIFIED[/bold green] | Total Signed Entries: {res.total_entries} | Cryptographic Hash Chain Intact",
                style="bold green",
            )
        else:
            banner = Panel(
                f"[bold red]⚠️ TAMPER WARNING: AUDIT LOG CHAIN BROKEN![/bold red] {res.tamper_reason}",
                style="bold red",
            )

        table = Table(expand=True, border_style="blue")
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("Event Type", style="bold yellow")
        table.add_column("Prev Hash", style="dim")
        table.add_column("This Hash", style="bold white")

        entries = self.repo.list_audit_entries(limit=30)
        for entry in entries:
            table.add_row(
                entry.timestamp[11:19] if len(entry.timestamp) >= 19 else entry.timestamp,
                entry.event_type,
                entry.prev_hash[:12] + "...",
                entry.this_hash[:12] + "...",
            )

        layout["banner"].update(banner)
        layout["table"].update(Panel(table, title="[bold white]Append-Only Hash-Chained Audit Trail[/bold white]", border_style="blue"))
        return layout

    def render_config_view(self) -> Panel:
        body = Text()
        body.append("--- Active Configuration & Deterministic Rules ---\n\n", style="bold cyan")
        body.append(f"Dry Run Default:      {self.config.dry_run}\n", style="bold yellow")
        body.append(f"Firewall Adapter:     {self.config.firewall_adapter}\n", style="magenta")
        body.append(f"Default TTL:          {self.config.default_ttl_seconds} seconds\n", style="green")
        body.append(f"Claude AI Model:      {self.config.claude_model}\n", style="cyan")
        body.append(f"Database Location:    {self.config.db_path}\n\n", style="dim")

        body.append("--- Rule Thresholds ---\n", style="bold white")
        body.append(f"Brute Force:          {self.config.brute_force_threshold} failures in {self.config.brute_force_window}s\n")
        body.append(f"Port Scan:            {self.config.port_scan_threshold} ports in {self.config.port_scan_window}s\n")
        body.append(f"Privilege Escalation: {self.config.priv_esc_threshold} attempts in {self.config.priv_esc_window}s\n\n")

        body.append("--- Mandatory System Allowlist ---\n", style="bold green")
        allowlist = self.repo.get_allowlist()
        for item in allowlist:
            body.append(f"- {item.ip_or_cidr:<20} ({item.reason})\n", style="dim green")

        return Panel(body, title="[bold white]Rules & Safety Configuration[/bold white]", border_style="green")
