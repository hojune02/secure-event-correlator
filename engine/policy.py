from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from engine.models import CorrelationDecision, EventRecord
from engine.portfolio import PaperPortfolio


DecisionType = Literal["ALLOW", "THROTTLE", "BLOCK"]


@dataclass(frozen=True)
class PolicyDecision:
    event_id: str
    strategy_id: str
    symbol: str
    decision: DecisionType
    reasons: list[str] = field(default_factory=list)
    context: dict = field(default_factory=dict)


class RiskPolicyEngine:
    """
    Day 4: risk state + policy enforcement.
    Consumes correlation decision + portfolio state and produces FINAL decision.
    """

    def __init__(
        self,
        portfolio: PaperPortfolio,
        max_daily_loss: float = -200.0,          # realised pnl threshold (negative)
        cooldown_after_loss_seconds: int = 300,  # 5 minutes
        max_open_positions: int = 1,             # per (strategy, symbol) in MVP
        default_qty: float = 1.0,                # paper quantity
    ):
        self.portfolio = portfolio
        self.max_daily_loss = max_daily_loss
        self.cooldown_after_loss = timedelta(seconds=cooldown_after_loss_seconds)
        self.max_open_positions = max_open_positions
        self.default_qty = default_qty

    def evaluate(
        self,
        record: EventRecord,
        corr: CorrelationDecision,
        entry_price: Optional[float],
    ) -> PolicyDecision:
        reasons: list[str] = []
        context: dict = {"correlation_decision": corr.decision, "correlation_reasons": corr.reasons}

        # Start from correlation output
        decision: DecisionType = corr.decision

        # Pull risk state
        risk = self.portfolio.get_risk(record.strategy_id, record.symbol)
        now = datetime.now(timezone.utc)

        # Kill switch on daily loss
        context["realised_pnl"] = risk.realised_pnl
        context["max_drawdown"] = risk.max_drawdown

        ## kill_switch_active -> cooldown_active -> max_daily_loss_exceeded -> correlation consequences -> portfolio actions

        if risk.kill_switch:
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "BLOCK",
                                 reasons=["kill_switch_active"], context=context)
        
        # Cooldown enforcement
        if risk.cooldown_until_utc and now < risk.cooldown_until_utc:
            context["cooldown_until_utc"] = risk.cooldown_until_utc.isoformat()
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "BLOCK",
                                 reasons=["cooldown_active"], context=context)

        if risk.realised_pnl <= self.max_daily_loss:
            risk.kill_switch = True
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "BLOCK",
                                 reasons=["max_daily_loss_exceeded"], context=context)

        # Treat correlation BLOCK as final BLOCK
        if corr.decision == "BLOCK":
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "BLOCK",
                                 reasons=["correlation_block"], context=context)

        # Require price for paper trading
        if entry_price is None:
            # allow signal through for monitoring, but block execution because we cannot compute PnL/position
            # (you can decide to THROTTLE instead; BLOCK is safest)
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "THROTTLE",
                                 reasons=["missing_entry_price"], context=context)

        # Simple paper execution logic (state evolution)
        pos = self.portfolio.get_position(record.strategy_id, record.symbol)

        if pos is None:
            # Open new position only if ALLOW (or THROTTLE -> you could reduce size; MVP blocks execution)
            if decision != "ALLOW":
                return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "THROTTLE",
                                     reasons=["correlation_throttle"], context=context)

            self.portfolio.open_position(record.strategy_id, record.symbol, record.side, self.default_qty, entry_price)
            context["paper_action"] = "open"
            context["qty"] = self.default_qty
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "ALLOW",
                                 reasons=["opened_position"], context=context)

        # If we already have a position:
        # - If same side: do nothing (avoid pyramiding in MVP)
        # - If opposite side: close existing and optionally open the new one
        if pos.side == record.side:
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "THROTTLE",
                                 reasons=["position_already_open_same_side"], context=context)

        # Opposite side: close and record pnl
        pnl = self.portfolio.close_position(record.strategy_id, record.symbol, entry_price)
        context["paper_action"] = "close"
        context["closed_pnl"] = pnl
        context["realised_pnl"] = pnl

        # Cooldown if loss
        if pnl < 0:
            risk.cooldown_until_utc = now + self.cooldown_after_loss
            context["cooldown_set_until_utc"] = risk.cooldown_until_utc.isoformat()
            # After a loss, block immediate flip to avoid churn
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "BLOCK",
                                 reasons=["loss_cooldown_triggered"], context=context)

        # If profit and correlation is ALLOW, allow flip-open
        if corr.decision == "ALLOW":
            self.portfolio.open_position(record.strategy_id, record.symbol, record.side, self.default_qty, entry_price)
            context["paper_action"] = "flip_open"
            context["qty"] = self.default_qty
            return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "ALLOW",
                                 reasons=["closed_then_opened"], context=context)

        return PolicyDecision(record.event_id, record.strategy_id, record.symbol, "THROTTLE",
                             reasons=["closed_position_but_throttled"], context=context)
