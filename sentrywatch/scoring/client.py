import json
import logging
from dataclasses import dataclass
from typing import Optional
from sentrywatch.config import SentrywatchConfig
from sentrywatch.db.repository import Incident, IPReputation

logger = logging.getLogger("sentrywatch.scoring")


@dataclass
class ScoreResult:
    severity_score: int
    rationale: str
    recommended_action: str  # monitor | review | consider_block
    confidence: str  # low | medium | high
    is_fallback: bool = False


class ScoringClient:
    def __init__(self, config: SentrywatchConfig):
        self.config = config

    def score_incident(
        self, incident: Incident, ip_rep: Optional[IPReputation] = None
    ) -> ScoreResult:
        """Call Claude API for advisory incident severity scoring, with fail-safe fallback."""
        if not self.config.anthropic_api_key:
            return self._heuristic_fallback(incident, ip_rep, rationale_prefix="[Offline Mode] ")

        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
            prompt = self._build_prompt(incident, ip_rep)

            response = client.messages.create(
                model=self.config.claude_model,
                max_tokens=300,
                temperature=0.2,
                system="You are a senior SOC security analyst. Analyze the incident and respond ONLY with raw JSON matching the requested schema.",
                messages=[{"role": "user", "content": prompt}],
            )

            text_resp = response.content[0].text.strip()
            # Parse JSON from response
            data = json.loads(text_resp)
            return ScoreResult(
                severity_score=int(data.get("severity_score", 50)),
                rationale=str(data.get("rationale", "AI severity score calculated")),
                recommended_action=str(data.get("recommended_action", "review")),
                confidence=str(data.get("confidence", "medium")),
                is_fallback=False,
            )
        except Exception as e:
            logger.warning(f"Claude API scoring unavailable ({e}). Falling back to heuristic score.")
            return self._heuristic_fallback(
                incident, ip_rep, rationale_prefix=f"[API Fallback: {e}] "
            )

    def _build_prompt(self, incident: Incident, ip_rep: Optional[IPReputation]) -> str:
        rep_text = (
            f"Seen {ip_rep.first_seen} to {ip_rep.last_seen}, counts: {ip_rep.incident_counts}, rep_score: {ip_rep.reputation_score}"
            if ip_rep
            else "No prior history"
        )

        return f"""
Analyze this security incident:
- Incident Type: {incident.incident_type}
- Source IP: {incident.source_ip or 'Unknown'}
- Created At: {incident.created_at}
- IP History: {rep_text}
- Evidence / Log:
{incident.raw_evidence}

Provide a JSON object with keys:
- "severity_score": integer (0 to 100)
- "rationale": short 1-2 sentence explanation
- "recommended_action": one of ["monitor", "review", "consider_block"]
- "confidence": one of ["low", "medium", "high"]
"""

    def _heuristic_fallback(
        self, incident: Incident, ip_rep: Optional[IPReputation], rationale_prefix: str = ""
    ) -> ScoreResult:
        rep_score = ip_rep.reputation_score if ip_rep else 20
        inc_weights = {
            "brute_force": 60,
            "port_scan": 55,
            "priv_esc": 85,
            "anomalous_outbound": 75,
            "suspicious_process": 90,
        }
        base_score = inc_weights.get(incident.incident_type, 50)
        final_score = min(100, int((base_score * 0.7) + (rep_score * 0.3)))

        if final_score >= 80:
            rec_action = "consider_block"
            confidence = "high"
        elif final_score >= 50:
            rec_action = "review"
            confidence = "medium"
        else:
            rec_action = "monitor"
            confidence = "low"

        rationale = f"{rationale_prefix}Deterministic fallback score derived from incident type ({incident.incident_type}) and IP reputation ({rep_score})."
        return ScoreResult(
            severity_score=final_score,
            rationale=rationale,
            recommended_action=rec_action,
            confidence=confidence,
            is_fallback=True,
        )
