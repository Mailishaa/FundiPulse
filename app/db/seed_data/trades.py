"""Construction trades as immutable module-level data.

A *trade* is the coarse grouping a Kenyan worker is hired under - the word on
the advert, and the word a site foreman asks for ("I need a fundi, two masons
and a plumber"). Skills (:mod:`app.db.seed_data.skills`) hang off a trade, so the
split matters: trades stay small and stable enough to appear on a button, and
skills stay specific enough to be worth matching on.

``display_order`` groups related trades and puts the highest-volume Kenyan
trades first, because the catalogue is rendered as a list in the app and the
first entries are what a new user actually sees.

The ``code`` values are the stable machine keys already referenced by the
specification and by the API; they are never reused after deactivation, so a
retired trade keeps resolving for historical work passports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class TradeSeed:
    """One row of the ``trades`` catalogue."""

    code: str
    name: str
    description: str
    display_order: int


#: Ordered trade catalogue: structure and finishing trades first, then services,
#: then plant and general labour.
TRADES: Final[tuple[TradeSeed, ...]] = (
    TradeSeed(
        code="MASONRY",
        name="Masonry",
        description=(
            "Laying concrete blocks, stones and bricks, and building walls, "
            "foundations, columns and drainage structures from set-out to "
            "plumb line."
        ),
        display_order=10,
    ),
    TradeSeed(
        code="CARPENTRY",
        name="Carpentry",
        description=(
            "Site timberwork: roof trusses and rafters, formwork timber, doors, "
            "frames, fittings and general finish carpentry on residential and "
            "commercial buildings."
        ),
        display_order=20,
    ),
    TradeSeed(
        code="FORMWORK_CARPENTRY",
        name="Formwork Carpentry",
        description=(
            "Building and striking the moulds that give fresh concrete its "
            "shape, using both timber formwork and steel shuttering panels for "
            "slabs, beams, columns and staircases."
        ),
        display_order=30,
    ),
    TradeSeed(
        code="REBAR_FIXING",
        name="Rebar Fixing",
        description=(
            "Cutting, bending and tying reinforcement to the bar bending "
            "schedule, including laps, chairs and cover blocks, ready for the "
            "concrete pour."
        ),
        display_order=40,
    ),
    TradeSeed(
        code="STEEL_FIXING",
        name="Steel Fixing",
        description=(
            "Erecting structural steel and fixing metalwork: reading the "
            "fabrication drawings, bolting and connecting portal frames, "
            "trusses and structural members."
        ),
        display_order=50,
    ),
    TradeSeed(
        code="SCAFFOLDING",
        name="Scaffolding",
        description=(
            "Erecting, tying and striking tube-and-coupler or system scaffold "
            "for access, working platforms and temporary works support."
        ),
        display_order=60,
    ),
    TradeSeed(
        code="ROOFING",
        name="Roofing",
        description=(
            "Laying and fixing roof coverings - iron sheet, tile and concrete "
            "tiles - and waterproofing, including sheeting, flashings, valleys "
            "and rainwater goods."
        ),
        display_order=70,
    ),
    TradeSeed(
        code="PLUMBING",
        name="Plumbing",
        description=(
            "Installing and testing water supply, drainage and sanitary "
            "services in buildings, from pipework in the slab to taps, WCs and "
            "kitchen units."
        ),
        display_order=80,
    ),
    TradeSeed(
        code="ELECTRICAL",
        name="Electrical",
        description=(
            "Installing and terminating wiring, conduits, distribution boards "
            "and fittings, and testing installations before handover."
        ),
        display_order=90,
    ),
    TradeSeed(
        code="HVAC",
        name="HVAC",
        description=(
            "Fitting and servicing mechanical systems: air conditioning, split "
            "and cassette units, refrigeration, extract fans and ventilation "
            "ducts."
        ),
        display_order=100,
    ),
    TradeSeed(
        code="PAINTING_AND_DECORATING",
        name="Painting and Decorating",
        description=(
            "Surface preparation, priming and painting of walls, ceilings, "
            "metalwork and timber, plus decorative finishes and wallcoverings."
        ),
        display_order=110,
    ),
    TradeSeed(
        code="PLASTERING",
        name="Plastering",
        description=(
            "Rendering and plastering walls and ceilings to a true finish, "
            "including scratch coats, skimming and decorative smooth coats."
        ),
        display_order=120,
    ),
    TradeSeed(
        code="TILING",
        name="Tiling",
        description=(
            "Fixing ceramic, porcelain, stone and mosaic tiles to floors, "
            "walls and counters, with correct falls, spacing and grouting."
        ),
        display_order=130,
    ),
    TradeSeed(
        code="FLOORING",
        name="Flooring",
        description=(
            "Laying screeds and finish floors: vinyl, carpet, wood, terrazzo "
            "and resin systems, including levelling and joint preparation."
        ),
        display_order=140,
    ),
    TradeSeed(
        code="GLAZING",
        name="Glazing",
        description=(
            "Fitting and sealing glass and glazing units into frames, from "
            "household windows and doors to aluminium shopfronts and "
            "curtain-wall panels."
        ),
        display_order=150,
    ),
    TradeSeed(
        code="WELDING",
        name="Welding",
        description=(
            "Arc, MIG/MAG, TIG and gas welding of mild steel, stainless and "
            "aluminium for repairs, gates, tanks and structural fabrication."
        ),
        display_order=160,
    ),
    TradeSeed(
        code="MACHINE_OPERATION",
        name="Machine Operation",
        description=(
            "Operating and manoeuvring plant on site - excavators, graders, "
            "rollers, mixers and hoists - plus basic servicing and daily checks."
        ),
        display_order=170,
    ),
    TradeSeed(
        code="QUARRY_WORK",
        name="Quarry Work",
        description=(
            "Operating crushing and screening plant and working with aggregate "
            "at quarries and borrow pits, including loading and stockpiling."
        ),
        display_order=180,
    ),
    TradeSeed(
        code="GENERAL_LABOUR",
        name="General Labour",
        description=(
            "Site labouring: mixing by hand, shovelling, barrow runs, site "
            "cleanliness, loading and general support to the skilled trades."
        ),
        display_order=190,
    ),
    TradeSeed(
        code="LANDSCAPING",
        name="Landscaping",
        description=(
            "External works after handover: soil preparation, planting, turf "
            "laying, irrigation and hardscape paving and kerbing."
        ),
        display_order=200,
    ),
)

#: ``code`` -> trade, for callers that resolve a skill's trade in one lookup.
TRADES_BY_CODE: Final[dict[str, TradeSeed]] = {trade.code: trade for trade in TRADES}


def _assert_trades_are_sound() -> None:
    """Guard against a duplicate or empty code sneaking into the catalogue.

    A duplicate ``code`` would be rejected by the ``uq_trades_code`` constraint
    at seed time, but only *after* the first trade of that code had already
    been created, leaving a half-applied catalogue in the caller's transaction.
    """
    codes: set[str] = set()
    for trade in TRADES:
        if not trade.code.strip() or not trade.name.strip() or not trade.description.strip():
            raise ValueError(f"Trade {trade.code!r} is missing a required field")
        if trade.code in codes:
            raise ValueError(f"Duplicate trade code {trade.code!r}")
        codes.add(trade.code)
    if len(codes) != len(TRADES_BY_CODE):
        raise ValueError("TRADES_BY_CODE does not match TRADES")


_assert_trades_are_sound()
