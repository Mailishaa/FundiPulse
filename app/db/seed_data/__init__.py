"""Reference data used by the development seed script.

Split into three modules because they answer different questions:

* :mod:`~app.db.seed_data.counties` - *where* is the work (47 counties).
* :mod:`~app.db.seed_data.trades` - *what kind of* work (20 trades).
* :mod:`~app.db.seed_data.skills` - *what can this worker actually do* (skills).

Everything here is plain, immutable data with no database or settings imports,
so it can be imported by the seeder, by tests, and by scripts without a session
or a configured environment.
"""

from __future__ import annotations

from app.db.seed_data.counties import COUNTIES, REGIONS, CountySeed
from app.db.seed_data.skills import SKILLS, SkillSeed
from app.db.seed_data.trades import TRADES, TRADES_BY_CODE, TradeSeed

__all__ = [
    "COUNTIES",
    "REGIONS",
    "SKILLS",
    "TRADES",
    "TRADES_BY_CODE",
    "CountySeed",
    "SkillSeed",
    "TradeSeed",
]
