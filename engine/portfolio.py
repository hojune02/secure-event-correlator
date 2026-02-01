from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, date
from typing import Literal, Optional


Side = Literal["long", "short"]


@dataclass
class Position:
    side: Side
    qty: float
    entry_price: float
    entry_time_utc: datetime


@dataclass
class SymbolDailyRisk:
    day: date
    realised_pnl: float = 0.0
    peak_equity: float = 0.0   # for drawdown tracking
    equity: float = 0.0        # realised-only equity in MVP
    max_drawdown: float = 0.0
    kill_switch: bool = False
    cooldown_until_utc: Optional[datetime] = None


class PaperPortfolio:
    """
    MVP portfolio:
    - At most 1 open position per (strategy_id, symbol)
    - realised PnL only (unrealised ignored for simplicity)
    """
    def __init__(self):
        self._pos: dict[tuple[str, str], Position] = {}
        self._risk: dict[tuple[str, str], SymbolDailyRisk] = {}

    def get_position(self, strategy_id: str, symbol: str) -> Optional[Position]:
        return self._pos.get((strategy_id, symbol))

    def get_risk(self, strategy_id: str, symbol: str) -> SymbolDailyRisk:
        key = (strategy_id, symbol)
        today = datetime.now(timezone.utc).date()
        r = self._risk.get(key)
        if r is None or r.day != today:
            # reset daily state
            r = SymbolDailyRisk(day=today, realised_pnl=0.0, peak_equity=0.0, equity=0.0, max_drawdown=0.0)
            self._risk[key] = r
        return r

    def open_position(self, strategy_id: str, symbol: str, side: Side, qty: float, price: float) -> None:
        self._pos[(strategy_id, symbol)] = Position(
            side=side,
            qty=qty,
            entry_price=price,
            entry_time_utc=datetime.now(timezone.utc),
        )

    def close_position(self, strategy_id: str, symbol: str, exit_price: float) -> float:
        """
        Close position and return realised PnL (in price units * qty).
        """
        key = (strategy_id, symbol)
        pos = self._pos.pop(key, None)
        if pos is None:
            return 0.0

        if pos.side == "long":
            pnl = (exit_price - pos.entry_price) * pos.qty
        else:
            pnl = (pos.entry_price - exit_price) * pos.qty

        r = self.get_risk(strategy_id, symbol)
        r.realised_pnl += pnl
        r.equity = r.realised_pnl
        r.peak_equity = max(r.peak_equity, r.equity)
        r.max_drawdown = min(r.max_drawdown, r.equity - r.peak_equity)  # negative number

        return pnl
