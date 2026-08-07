"""
Assignment 11 — Audit Log (TODO 8b implemented).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}   # request_id -> start monotonic timestamp

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id.

        Args:
            user_id: Identifier for the user making the request.
            text: The raw input text sent by the user.
            request_id: Correlation ID; auto-generated if not provided.
        """
        rid = request_id or str(uuid.uuid4())
        self._open[rid] = time.monotonic()
        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "event": "input",
            "text": text,
            "blocked": None,
            "layer": None,
            "latency_ms": None,
        })

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, and latency; append to self.logs.

        Args:
            user_id: Identifier for the user.
            text: The response text (possibly redacted).
            blocked: Whether the response was blocked/modified.
            layer: Which pipeline layer acted (e.g. 'input_injection', 'output_filter').
            request_id: Correlation ID matching the corresponding record_input call.
        """
        rid = request_id or "unknown"
        start = self._open.pop(rid, None)
        latency_ms = round((time.monotonic() - start) * 1000, 2) if start else None

        self.logs.append({
            "request_id": rid,
            "user_id": user_id,
            "timestamp": utc_now_iso(),
            "event": "output",
            "text": text[:500],     # truncate long responses for storage
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        })

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk as a JSON array.

        Args:
            filepath: Destination path; parent directories are created if needed.
        """
        out = Path(filepath)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
