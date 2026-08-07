"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """Compute rates and append Alert objects when thresholds are exceeded.

        Checks three conditions:
          1. Block rate (blocked_requests / total_requests)
          2. Rate-limit hits absolute count
          3. Judge failure rate (judge_fails / judge_checks)

        Returns:
            List of Alert objects fired in this check.
        """
        fired: list[Alert] = []

        # 1. Block rate alert
        if self.total_requests > 0:
            block_rate = self.blocked_requests / self.total_requests
            if block_rate > self.block_rate_threshold:
                alert = Alert(
                    metric="block_rate",
                    value=round(block_rate, 4),
                    threshold=self.block_rate_threshold,
                    message=(
                        f"ALERT: Block rate {block_rate:.1%} exceeds threshold "
                        f"{self.block_rate_threshold:.1%}. Possible attack wave."
                    ),
                )
                fired.append(alert)
                self.alerts.append(alert)

        # 2. Rate-limit hits alert
        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            alert = Alert(
                metric="rate_limit_hits",
                value=float(self.rate_limit_hits),
                threshold=float(self.rate_limit_hit_threshold),
                message=(
                    f"ALERT: {self.rate_limit_hits} rate-limit hits, threshold "
                    f"{self.rate_limit_hit_threshold}. Possible flooding attack."
                ),
            )
            fired.append(alert)
            self.alerts.append(alert)

        # 3. Judge failure rate alert
        if self.judge_checks > 0:
            judge_fail_rate = self.judge_fails / self.judge_checks
            if judge_fail_rate > self.judge_fail_rate_threshold:
                alert = Alert(
                    metric="judge_fail_rate",
                    value=round(judge_fail_rate, 4),
                    threshold=self.judge_fail_rate_threshold,
                    message=(
                        f"ALERT: Judge fail rate {judge_fail_rate:.1%} exceeds "
                        f"threshold {self.judge_fail_rate_threshold:.1%}. "
                        f"Model may be producing unsafe outputs."
                    ),
                )
                fired.append(alert)
                self.alerts.append(alert)

        return fired

    def export_json(self, filepath: str = "outputs/metrics.json"):
        """Write metrics snapshot + alerts to JSON.

        Args:
            filepath: Destination path; parent directories created if needed.
        """
        import json
        from pathlib import Path

        # Run metrics check before exporting
        self.check_metrics()

        out = Path(filepath)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.snapshot(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
