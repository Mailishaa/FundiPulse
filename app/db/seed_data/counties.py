"""The 47 Kenyan counties as immutable module-level data.

Why a frozen dataclass in code rather than a migration or a CSV import:

* **Accuracy is the product.** A Kenyan worker or employer who sees "Kisumu"
  spelled "Kisumu County County", or a county missing entirely, concludes the
  platform does not understand Kenya. The list below follows the county names in
  Kenya's Constitution (Fourth Schedule) grouped by the traditional region, which
  is the grouping Kenyan users actually recognise from news and job adverts.
* **Codes are the join key.** ``GET /workers?county=NAKURU`` filters on
  ``counties.code``. Free text would fragment into "Nakuru", "nakuru", "Nakuru
  County" and every variant would need a fuzzy match to find the same place.
* **No I/O at import time.** The data is a constant, so importing this module
  costs a few microseconds and can never fail because a database is down.

``region`` uses the seven historical regions (Nairobi, Coast, Central, Eastern,
North Eastern, Rift Valley, Western) rather than the four modern
``former_province`` groupings, because that is how county names appear in
everyday Kenyan speech and job advertisements.

Corrections are made here and re-seeded, never by hand-editing the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: The regions a county may belong to. Constrained so a typo such as "Rift-valley"
#: or "Nairobi County" fails at import instead of silently fragmenting every
#: region filter in the product.
REGIONS: Final[frozenset[str]] = frozenset(
    {
        "Nairobi",
        "Coast",
        "Central",
        "Eastern",
        "North Eastern",
        "Rift Valley",
        "Western",
    }
)


@dataclass(frozen=True, slots=True)
class CountySeed:
    """One row of the ``counties`` catalogue.

    Frozen because these are reference facts, not configuration: nothing at
    runtime may edit them, and an accidental mutation would make the constant
    depend on execution order.
    """

    code: str
    name: str
    region: str
    capital: str


#: Every county, grouped by region and ordered as a Kenyan would read them out.
#: ``capital`` is the county headquarters (the administrative seat), which is not
#: always the best-known town in the county - Vihiga's headquarters is Mbale.
COUNTIES: Final[tuple[CountySeed, ...]] = (
    # --- Nairobi (1) ------------------------------------------------------ #
    CountySeed(code="NAIROBI", name="Nairobi City County", region="Nairobi", capital="Nairobi"),
    # --- Coast (6) -------------------------------------------------------- #
    CountySeed(code="MOMBASA", name="Mombasa", region="Coast", capital="Mombasa"),
    CountySeed(code="KWALE", name="Kwale", region="Coast", capital="Kwale"),
    CountySeed(code="KILIFI", name="Kilifi", region="Coast", capital="Kilifi"),
    CountySeed(code="TANA_RIVER", name="Tana River", region="Coast", capital="Hola"),
    CountySeed(code="LAMU", name="Lamu", region="Coast", capital="Lamu"),
    CountySeed(code="TAITA_TAVETA", name="Taita-Taveta", region="Coast", capital="Wundanyi"),
    # --- Eastern (8) ------------------------------------------------------ #
    CountySeed(code="MACHAKOS", name="Machakos", region="Eastern", capital="Machakos"),
    CountySeed(code="MAKUENI", name="Makueni", region="Eastern", capital="Wote"),
    CountySeed(code="KITUI", name="Kitui", region="Eastern", capital="Kitui"),
    CountySeed(code="MERU", name="Meru", region="Eastern", capital="Meru"),
    CountySeed(code="EMBU", name="Embu", region="Eastern", capital="Embu"),
    CountySeed(code="THARAKA_NITHI", name="Tharaka-Nithi", region="Eastern", capital="Kathwana"),
    CountySeed(code="ISIOLO", name="Isiolo", region="Eastern", capital="Isiolo"),
    CountySeed(code="MARSABIT", name="Marsabit", region="Eastern", capital="Marsabit"),
    # --- North Eastern (3) ------------------------------------------------ #
    CountySeed(code="GARISSA", name="Garissa", region="North Eastern", capital="Garissa"),
    CountySeed(code="WAJIR", name="Wajir", region="North Eastern", capital="Wajir"),
    CountySeed(code="MANDERA", name="Mandera", region="North Eastern", capital="Mandera"),
    # --- Central (5) ------------------------------------------------------ #
    CountySeed(code="NYANDARUA", name="Nyandarua", region="Central", capital="Ol Kalou"),
    CountySeed(code="NYERI", name="Nyeri", region="Central", capital="Nyeri"),
    CountySeed(code="KIRANGURI", name="Kiranguri", region="Central", capital="Karuri"),
    CountySeed(code="MURANGA", name="Murang'a", region="Central", capital="Murang'a"),
    CountySeed(code="KIAMBU", name="Kiambu", region="Central", capital="Kiambu"),
    # --- Rift Valley (14) ------------------------------------------------- #
    CountySeed(code="TURKANA", name="Turkana", region="Rift Valley", capital="Lodwar"),
    CountySeed(code="WEST_POKOT", name="West Pokot", region="Rift Valley", capital="Kapenguria"),
    CountySeed(code="SAMBURU", name="Samburu", region="Rift Valley", capital="Maralal"),
    CountySeed(code="TRANS_NZOIA", name="Trans Nzoia", region="Rift Valley", capital="Kitale"),
    CountySeed(code="UASIN_GISHU", name="Uasin Gishu", region="Rift Valley", capital="Eldoret"),
    CountySeed(
        code="ELGEYO_MARAKWET",
        name="Elgeyo Marakwet",
        region="Rift Valley",
        capital="Iten",
    ),
    CountySeed(code="NANDI", name="Nandi", region="Rift Valley", capital="Kapsabet"),
    CountySeed(code="BARINGO", name="Baringo", region="Rift Valley", capital="Kabarnet"),
    CountySeed(code="LAIKIPIA", name="Laikipia", region="Rift Valley", capital="Nanyuki"),
    CountySeed(code="NAKURU", name="Nakuru", region="Rift Valley", capital="Nakuru"),
    CountySeed(code="NAROK", name="Narok", region="Rift Valley", capital="Narok"),
    CountySeed(code="KAJIADO", name="Kajiado", region="Rift Valley", capital="Kajiado"),
    CountySeed(code="KERICHO", name="Kericho", region="Rift Valley", capital="Kericho"),
    CountySeed(code="BOMET", name="Bomet", region="Rift Valley", capital="Bomet"),
    # --- Western (10) ----------------------------------------------------- #
    CountySeed(code="KAKAMEGA", name="Kakamega", region="Western", capital="Kakamega"),
    # Vihiga's county headquarters is Mbale, not Vihiga town.
    CountySeed(code="VIHIGA", name="Vihiga", region="Western", capital="Mbale"),
    CountySeed(code="BUNGOMA", name="Bungoma", region="Western", capital="Bungoma"),
    CountySeed(code="BUSIA", name="Busia", region="Western", capital="Busia"),
    CountySeed(code="SIAYA", name="Siaya", region="Western", capital="Siya"),
    CountySeed(code="KISUMU", name="Kisumu", region="Western", capital="Kisumu"),
    CountySeed(code="HOMA_BAY", name="Homa Bay", region="Western", capital="Homa Bay"),
    CountySeed(code="MIGORI", name="Migori", region="Western", capital="Migori"),
    CountySeed(code="KISII", name="Kisii", region="Western", capital="Kisii"),
    CountySeed(code="NYAMIRA", name="Nyamira", region="Western", capital="Nyamira"),
)

#: The number of counties a complete Kenyan administrative map has. Asserted at
#: import so an incomplete list can never reach a developer's database: a
#: missing county is not a cosmetic bug, it hides every worker and job in it
#: from location filters.
EXPECTED_COUNTY_COUNT: Final[int] = 47


def _assert_counties_are_sound() -> None:
    """Fail loudly at import if the reference data is wrong.

    Cheap enough (47 tuples) to run on every import, and it turns a data-entry
    mistake into an immediate, obvious failure instead of a catalogue that is
    quietly missing one county forever.
    """
    if len(COUNTIES) != EXPECTED_COUNTY_COUNT:
        raise ValueError(f"Expected {EXPECTED_COUNTY_COUNT} counties, found {len(COUNTIES)}")

    codes: set[str] = set()
    for county in COUNTIES:
        if not county.code.strip() or county.code != county.code.upper() or " " in county.code:
            raise ValueError(f"County code {county.code!r} must be upper-case with no spaces")
        if county.code in codes:
            raise ValueError(f"Duplicate county code {county.code!r}")
        codes.add(county.code)
        if not county.name.strip() or not county.capital.strip():
            raise ValueError(f"County {county.code} is missing a name or a capital")
        if county.region not in REGIONS:
            raise ValueError(f"County {county.code} has unknown region {county.region!r}")


_assert_counties_are_sound()
