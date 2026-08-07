"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # 1. High-risk actions always escalate regardless of confidence
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type} — mandatory human review",
                priority="high",
                requires_human=True,
            )

        # 2. Route by confidence threshold
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence — safe to auto-send",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs human review before sending",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating to human immediately",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Money Transfer Approval",
        "trigger": "User requests a transfer of >= 50,000,000 VND (50 million) or any "
                   "international wire transfer, OR the action_type is 'transfer_money' "
                   "with an amount exceeding the configured threshold.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Reviewer sees: (1) sender account & balance, (2) recipient name "
                          "& account number, (3) transfer amount & currency, "
                          "(4) agent-proposed reason/memo, (5) diff vs. last 3 transfers "
                          "for anomaly detection, (6) proposed API payload before sending.",
        "example": "Customer asks: 'Transfer 200 million VND to account 0123456789 at ABC Bank.' "
                   "Agent prepares the request. Before executing, a bank officer reviews "
                   "the beneficiary, amount, and any mismatch with historical patterns.",
        "approval_path": "Approve → agent executes transfer and records 'APPROVED' decision. "
                         "Reject → agent informs customer the request was declined and logs reason. "
                         "Timeout (120 s) → agent rejects automatically (fail closed) and "
                         "notifies customer to call the branch.",
        "audit_fields": "correlation_id (UUID), user_id, intent='large_transfer', "
                        "proposed_action=<transfer payload diff>, reviewer_id, "
                        "reviewer_decision (approve|reject|timeout), decision_timestamp, "
                        "latency_ms, alert_flags (e.g. new_beneficiary, amount_spike).",
    },
    {
        "id": 2,
        "name": "Personal Information Update",
        "trigger": "Agent proposes to change KYC fields: legal name, date of birth, "
                   "phone number, address, or identity document number. "
                   "action_type must be 'update_personal_info'.",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Reviewer sees: (1) current record (before), (2) proposed record (after), "
                          "(3) side-by-side diff of changed fields, (4) supporting document "
                          "(image/ID scan if provided), (5) last update timestamp and channel.",
        "example": "Customer submits a new CCCD photo to update their ID number from "
                   "001234567890 to 001234567999. Agent extracts the new number and presents "
                   "a diff. A compliance officer verifies the document matches the new number "
                   "before the update is committed.",
        "approval_path": "Approve → system updates KYC record and sends SMS confirmation. "
                         "Reject → no change; agent informs customer to visit a branch. "
                         "Timeout (300 s) → request is queued for next available officer; "
                         "customer is informed via email.",
        "audit_fields": "correlation_id (UUID), user_id, intent='kyc_update', "
                        "field_diff={'phone': ('old', 'new'), ...}, document_ref, "
                        "reviewer_id, reviewer_decision, decision_timestamp, "
                        "channel (web|mobile|chatbot).",
    },
    {
        "id": 3,
        "name": "Account Closure Request",
        "trigger": "User explicitly requests to close an account "
                   "(action_type='close_account') or the agent detects intent "
                   "such as 'cancel my account', 'delete account', 'đóng tài khoản'. "
                   "Always escalates regardless of confidence score.",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Reviewer sees: (1) account number & type (savings/checking/loan), "
                          "(2) current balance and any active loans or auto-payments linked, "
                          "(3) closure reason provided by customer, "
                          "(4) regulatory hold check (AML/KYC flags), "
                          "(5) agent recommendation (can close / cannot close with reason).",
        "example": "Customer says: 'I want to close my savings account ending in 4521.' "
                   "The account has a balance of 5,000,000 VND and an active auto-payment. "
                   "The agent flags the auto-payment conflict and presents a summary. "
                   "A customer-service manager decides whether to proceed after verifying "
                   "the customer's identity via OTP.",
        "approval_path": "Approve → agent initiates closure workflow, disburses remaining "
                         "balance to linked account, sends closure confirmation email. "
                         "Reject → agent explains why closure was denied (e.g. active loan). "
                         "Timeout (600 s) → request is parked; customer contacted within 24 h "
                         "by the branch (fail safe — no irreversible action taken).",
        "audit_fields": "correlation_id (UUID), user_id, account_id, intent='account_closure', "
                        "balance_at_request, active_products_count, aml_flag (bool), "
                        "reviewer_id, reviewer_decision, decision_timestamp, "
                        "otp_verified (bool), closure_channel.",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
