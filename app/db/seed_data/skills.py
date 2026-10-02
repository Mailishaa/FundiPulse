"""Skills as immutable module-level data.

A *skill* is the specific, verifiable capability an employer actually searches
for ("can you do rebar lapping?"), as opposed to a trade, which is the broad
role the worker is hired under. Matching a job to a worker happens at the skill
level, so the catalogue has to be concrete.

``trade_code`` is ``None`` for skills that genuinely span trades - supervision,
safety, reading drawings. Those are attached directly to the worker profile
without a trade, because a plasterer who reads a drawing well should be findable
by a tiling job just as much as by a plastering job.

``trade_code`` is a *code* rather than a foreign key because this module is plain
data: it must not need a database session to be importable. :func:`assert_skills_are_sound`
resolves every one of them against :data:`app.db.seed_data.trades.TRADES` at
import time, so a typo becomes a startup failure rather than a ``NULL``
``trade_id`` in the catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.db.seed_data.trades import TRADES_BY_CODE


@dataclass(frozen=True, slots=True)
class SkillSeed:
    """One row of the ``skills`` catalogue."""

    code: str
    name: str
    trade_code: str | None
    description: str
    display_order: int


#: Ordered skill catalogue. Cross-trade skills come first because they apply to
#: every passport; the rest follow in trade order so the admin catalogue reads
#: as a coherent list.
SKILLS: Final[tuple[SkillSeed, ...]] = (
    # --- Cross-trade (no owning trade) ----------------------------------- #
    SkillSeed(
        code="SITE_SUPERVISION",
        name="Site Supervision",
        trade_code=None,
        description=(
            "Running a site or a section of one: daily allocation of gangs, "
            "coordinating trades, and reporting progress and delays."
        ),
        display_order=10,
    ),
    SkillSeed(
        code="SAFETY_COMPLIANCE",
        name="Safety Compliance",
        trade_code=None,
        description=(
            "Working to the site safety plan: PPE discipline, toolbox talks, "
            "scaffold and excavation safety, and incident reporting."
        ),
        display_order=20,
    ),
    SkillSeed(
        code="READING_DRAWINGS",
        name="Reading Drawings",
        trade_code=None,
        description=(
            "Reading and explaining architectural and structural drawings, "
            "sections and schedules, and setting out from them on site."
        ),
        display_order=30,
    ),
    SkillSeed(
        code="SITE_MEASUREMENTS",
        name="Site Measurement",
        trade_code=None,
        description=(
            "Taking and recording site measurements for quantities, progress "
            "claims and as-built records."
        ),
        display_order=40,
    ),
    SkillSeed(
        code="TEAM_LEADERSHIP",
        name="Team Leadership",
        trade_code=None,
        description=(
            "Leading a gang of labourers, training less experienced workers and "
            "holding the pace of a section to programme."
        ),
        display_order=50,
    ),
    SkillSeed(
        code="QUALITY_CONTROL",
        name="Quality Control",
        trade_code=None,
        description=(
            "Inspecting completed work against the specification and drawings, "
            "and rejecting defective work before it is covered up."
        ),
        display_order=60,
    ),
    SkillSeed(
        code="WORKING_AT_HEIGHT",
        name="Working at Height",
        trade_code=None,
        description=(
            "Working safely on ladders, scaffolds, formwork and roof structures, "
            "including the use of harness and fall-arrest equipment."
        ),
        display_order=70,
    ),
    SkillSeed(
        code="MATERIAL_HANDLING",
        name="Material Handling",
        trade_code=None,
        description=(
            "Loading, unloading, stacking and moving materials safely on site, "
            "including manual handling and basic plant operation."
        ),
        display_order=80,
    ),
    SkillSeed(
        code="ESTIMATION_AND_COSTING",
        name="Estimation and Costing",
        trade_code=None,
        description=(
            "Pricing work from drawings: measuring, pricing labour, materials "
            "and plant, and preparing bills of quantities for tender."
        ),
        display_order=90,
    ),
    SkillSeed(
        code="FIRST_AID_ON_SITE",
        name="First Aid on Site",
        trade_code=None,
        description=(
            "Holding a recognised first aid certificate and providing initial "
            "care, including casualty handling on an active site."
        ),
        display_order=100,
    ),
    # --- Masonry ---------------------------------------------------------- #
    SkillSeed(
        code="BLOCK_LAYING",
        name="Block Laying",
        trade_code="MASONRY",
        description=(
            "Laying concrete blocks to line and level, bonding corners, "
            "terminations and openings correctly."
        ),
        display_order=110,
    ),
    SkillSeed(
        code="STONE_MASONRY",
        name="Stone Masonry",
        trade_code="MASONRY",
        description=(
            "Building in natural and dressed stone, including dry stone walls "
            "and stone finishes for feature walls."
        ),
        display_order=120,
    ),
    SkillSeed(
        code="MORTAR_AND_MIXING",
        name="Mortar and Mixing",
        trade_code="MASONRY",
        description=(
            "Mixing mortar to the right mix ratio and consistency, and "
            "premixing and curing concrete by hand where no mixer is available."
        ),
        display_order=130,
    ),
    # --- Carpentry -------------------------------------------------------- #
    SkillSeed(
        code="TIMBER_FRAMING",
        name="Timber Framing",
        trade_code="CARPENTRY",
        description=(
            "Erecting wall and roof framing from timber, including trusses, "
            "rafters and strutting to the engineer's drawings."
        ),
        display_order=140,
    ),
    SkillSeed(
        code="DOORS_WINDOWS_FITTING",
        name="Doors and Windows Fitting",
        trade_code="CARPENTRY",
        description=(
            "Fitting, squaring and hanging doors, frames, windows and ironmongery, "
            "including architraves and mouldings."
        ),
        display_order=150,
    ),
    SkillSeed(
        code="TIMBER_TEMPLATE_WORK",
        name="Timber Template Work",
        trade_code="CARPENTRY",
        description=(
            "Cutting and setting out timber templates and moulds used to form "
            "concrete work and to repeat profiles accurately."
        ),
        display_order=160,
    ),
    # --- Formwork carpentry ------------------------------------------------ #
    SkillSeed(
        code="TIMBER_FORMWORK_ASSEMBLY",
        name="Timber Formwork Assembly",
        trade_code="FORMWORK_CARPENTRY",
        description=(
            "Assembling, bracing and striking timber formwork for slabs, "
            "beams, columns and walls within the required cure times."
        ),
        display_order=170,
    ),
    SkillSeed(
        code="STEEL_SHUTTERING_FIXING",
        name="Steel Shuttering Fixing",
        trade_code="FORMWORK_CARPENTRY",
        description=(
            "Handling and assembling panel and table shuttering systems, "
            "including props, walers and release oil."
        ),
        display_order=180,
    ),
    # --- Rebar fixing ------------------------------------------------------ #
    SkillSeed(
        code="REBAR_CUTTING_AND_BENDING",
        name="Rebar Cutting and Bending",
        trade_code="REBAR_FIXING",
        description=(
            "Cutting, bending and tagging reinforcement to the bar bending "
            "schedule using manual and power cutters."
        ),
        display_order=190,
    ),
    SkillSeed(
        code="REBAR_TYING_AND_LAPPING",
        name="Rebar Tying and Lapping",
        trade_code="REBAR_FIXING",
        description=(
            "Tying reinforcement mesh and bars at the correct spacing and lap "
            "length, and making cold-worked bends on site."
        ),
        display_order=200,
    ),
    SkillSeed(
        code="REBAR_CHAIRING_AND_COVER",
        name="Rebar Chairing and Cover",
        trade_code="REBAR_FIXING",
        description=(
            "Placing chairs, links and cover blocks so reinforcement sits at "
            "the specified cover before the pour."
        ),
        display_order=210,
    ),
    # --- Plumbing ---------------------------------------------------------- #
    SkillSeed(
        code="WATER_SUPPLY_INSTALLATION",
        name="Water Supply Installation",
        trade_code="PLUMBING",
        description=(
            "Installing cold and hot water pipework in PVC, copper or PEX, "
            "including tanks, pumps, risers and pressure testing."
        ),
        display_order=220,
    ),
    SkillSeed(
        code="DRAINAGE_INSTALLATION",
        name="Drainage Installation",
        trade_code="PLUMBING",
        description=(
            "Laying soil, waste and rainwater pipework with correct falls, "
            "rodding access, manholes and septic connections."
        ),
        display_order=230,
    ),
    SkillSeed(
        code="SANITARY_FIXTURE_INSTALLATION",
        name="Sanitary Fixture Installation",
        trade_code="PLUMBING",
        description=(
            "Installing and commissioning WCs, basins, baths, sinks and "
            "instantaneous heaters, including their traps and connections."
        ),
        display_order=240,
    ),
    # --- Electrical -------------------------------------------------------- #
    SkillSeed(
        code="CONDUIT_AND_CABLE_INSTALLATION",
        name="Conduit and Cable Installation",
        trade_code="ELECTRICAL",
        description=(
            "Installing conduit, trunking and cable from distribution board to "
            "final outlets, including underground feeders."
        ),
        display_order=250,
    ),
    SkillSeed(
        code="WIRING_AND_ACCESSORIES",
        name="Wiring and Accessories",
        trade_code="ELECTRICAL",
        description=(
            "Terminating and connecting fittings, sockets, switches and lamp "
            "points, and setting out earthing and bonding."
        ),
        display_order=260,
    ),
    SkillSeed(
        code="ELECTRICAL_TESTING_AND_COMMISSIONING",
        name="Electrical Testing and Commissioning",
        trade_code="ELECTRICAL",
        description=(
            "Continuity, insulation and earth resistance testing and reporting "
            "before an installation is energised or handed over."
        ),
        display_order=270,
    ),
    # --- HVAC -------------------------------------------------------------- #
    SkillSeed(
        code="AIR_CONDITIONING_INSTALLATION",
        name="Air Conditioning Installation",
        trade_code="HVAC",
        description=(
            "Installing split, cassette and packaged air conditioning units, "
            "including refrigerant piping, drainage and control wiring."
        ),
        display_order=280,
    ),
    SkillSeed(
        code="REFRIGERATION_SERVICE",
        name="Refrigeration Service",
        trade_code="HVAC",
        description=(
            "Charging, leak testing and servicing refrigeration circuits and cold room equipment."
        ),
        display_order=290,
    ),
    SkillSeed(
        code="VENTILATION_AND_EXTRACTION",
        name="Ventilation and Extraction",
        trade_code="HVAC",
        description=(
            "Fitting and ducting extract and supply ventilation systems, "
            "cooker hoods and smoke exhaust fans."
        ),
        display_order=300,
    ),
    # --- Painting and decorating ------------------------------------------- #
    SkillSeed(
        code="SURFACE_PREPARATION",
        name="Surface Preparation",
        trade_code="PAINTING_AND_DECORATING",
        description=(
            "Filling, skimming, sanding and treating walls and ceilings so a "
            "coating adheres and a finish comes out flat."
        ),
        display_order=310,
    ),
    SkillSeed(
        code="WALL_PAINTING",
        name="Wall Painting",
        trade_code="PAINTING_AND_DECORATING",
        description=(
            "Applying emulsion, oil, enamel and texture coats to walls and "
            "ceilings by brush, roller or spray, inside and out."
        ),
        display_order=320,
    ),
    SkillSeed(
        code="DECORATIVE_FINISHING",
        name="Decorative Finishing",
        trade_code="PAINTING_AND_DECORATING",
        description=(
            "Textured finishes, wallpaper, stencil and special-effect coatings "
            "for feature walls and commercial interiors."
        ),
        display_order=330,
    ),
    # --- Plastering -------------------------------------------------------- #
    SkillSeed(
        code="WALL_RENDERING",
        name="Wall Rendering",
        trade_code="PLASTERING",
        description=(
            "Rendering block or stone walls in cement mortar, including "
            "weathering and keying coats and external render."
        ),
        display_order=340,
    ),
    SkillSeed(
        code="SKIMMING_AND_FINISH_COATS",
        name="Skimming and Finish Coats",
        trade_code="PLASTERING",
        description=(
            "Applying finish plaster and gypsum skim to produce a true, flat "
            "surface ready for painting."
        ),
        display_order=350,
    ),
    # --- Tiling ------------------------------------------------------------ #
    SkillSeed(
        code="TILING_PREPARATION_AND_GROUTING",
        name="Tiling Preparation and Grouting",
        trade_code="TILING",
        description=(
            "Preparing screeds and adhesives, setting out for fall and alignment, "
            "and grouting and sealing joints."
        ),
        display_order=360,
    ),
    SkillSeed(
        code="CERAMIC_TILE_FIXING",
        name="Ceramic Tile Fixing",
        trade_code="TILING",
        description=(
            "Fixing ceramic, porcelain and mosaic tiles to floors, walls and "
            "benches, including cuts around fittings and corners."
        ),
        display_order=370,
    ),
    # --- Flooring ----------------------------------------------------------- #
    SkillSeed(
        code="SCREED_AND_FLOOR_SCREEDS",
        name="Screed and Floor Screeds",
        trade_code="FLOORING",
        description=(
            "Levelling floors with cement and anhydrite screeds to the required "
            "flatness and fall before a finish floor is laid."
        ),
        display_order=380,
    ),
    SkillSeed(
        code="SOFT_FLOOR_FITTING",
        name="Soft Floor Fitting",
        trade_code="FLOORING",
        description=(
            "Fitting carpet, vinyl and rubber sheet and tile flooring, "
            "including underlay, trimming and seams."
        ),
        display_order=390,
    ),
    SkillSeed(
        code="RESIN_FLOOR_COATING",
        name="Resin Floor Coating",
        trade_code="FLOORING",
        description=(
            "Applying epoxy, polyurethane and acrylic resin coatings to "
            "concrete and screed in warehouses and commercial kitchens."
        ),
        display_order=400,
    ),
    # --- Glazing ------------------------------------------------------------ #
    SkillSeed(
        code="ALUMINIUM_GLAZING",
        name="Aluminium Glazing",
        trade_code="GLAZING",
        description=(
            "Glazing aluminium shopfronts, windows and doors with glass, using "
            "setting blocks, wedges and perimeter sealants."
        ),
        display_order=410,
    ),
    SkillSeed(
        code="GLASS_HANDLING_AND_SEALING",
        name="Glass Handling and Sealing",
        trade_code="GLAZING",
        description=(
            "Handling and storing glass safely, cutting to size where required, "
            "and applying structural and weather seals."
        ),
        display_order=420,
    ),
    # --- Roofing ------------------------------------------------------------ #
    SkillSeed(
        code="SHEET_ROOF_INSTALLATION",
        name="Sheet Roof Installation",
        trade_code="ROOFING",
        description=(
            "Laying and fixing iron sheet, tile and profiled roofing to trusses "
            "and purlins with correct overlaps and fixings."
        ),
        display_order=430,
    ),
    SkillSeed(
        code="ROOF_WATERPROOFING",
        name="Roof Waterproofing",
        trade_code="ROOFING",
        description=(
            "Applying waterproofing membranes, bituminous felt and liquid "
            "sealants to flat roofs and wet areas."
        ),
        display_order=440,
    ),
    SkillSeed(
        code="RAINWATER_GOODS",
        name="Rainwater Goods",
        trade_code="ROOFING",
        description=(
            "Installing gutters, downpipes, valleys and flashings so a roof "
            "actually sheds water where it is meant to."
        ),
        display_order=450,
    ),
    # --- Welding ------------------------------------------------------------ #
    SkillSeed(
        code="ARC_WELDING",
        name="Arc Welding",
        trade_code="WELDING",
        description=(
            "Stick (SMAW) welding of mild steel plate, sections and repair "
            "work in flat, horizontal and vertical positions."
        ),
        display_order=460,
    ),
    SkillSeed(
        code="MIG_MAG_WELDING",
        name="MIG/MAG Welding",
        trade_code="WELDING",
        description=(
            "MIG/MAG welding of mild steel and stainless, commonly used for "
            "gates, grilles and structural fabrication."
        ),
        display_order=470,
    ),
    SkillSeed(
        code="TIG_AND_GAS_WELDING",
        name="TIG and Gas Welding",
        trade_code="WELDING",
        description=(
            "TIG welding of stainless, aluminium and sheet metal, and oxy-fuel cutting and heating."
        ),
        display_order=480,
    ),
    # --- Steel fixing ------------------------------------------------------- #
    SkillSeed(
        code="STRUCTURAL_STEEL_ERECTION",
        name="Structural Steel Erection",
        trade_code="STEEL_FIXING",
        description=(
            "Craning and erecting portal frames, trusses and structural steel "
            "to the fabrication drawings."
        ),
        display_order=490,
    ),
    SkillSeed(
        code="BOLTING_AND_CONNECTIONS",
        name="Bolting and Connections",
        trade_code="STEEL_FIXING",
        description=(
            "Using and placing bolts, washers and connection plates, and "
            "checking bolt torque and alignment on site."
        ),
        display_order=500,
    ),
    # --- Scaffolding --------------------------------------------------------- #
    SkillSeed(
        code="TUBE_AND_COUPLER_SCAFFOLD",
        name="Tube and Coupler Scaffold",
        trade_code="SCAFFOLDING",
        description=(
            "Erecting, tying and loading tube-and-coupler scaffolds to the "
            "required working height, including access and ladders."
        ),
        display_order=510,
    ),
    SkillSeed(
        code="SCAFFOLD_INSPECTION_AND_TAGGING",
        name="Scaffold Inspection and Tagging",
        trade_code="SCAFFOLDING",
        description=(
            "Inspecting a scaffold, tagging it for use or prohibiting it, and "
            "issuing scaffold tags after each alteration."
        ),
        display_order=520,
    ),
    # --- Machine operation ---------------------------------------------------- #
    SkillSeed(
        code="EXCAVATOR_OPERATION",
        name="Excavator Operation",
        trade_code="MACHINE_OPERATION",
        description=(
            "Operating excavators for excavation, trenching, backfilling and "
            "loading, to the marked-out lines and depths."
        ),
        display_order=530,
    ),
    SkillSeed(
        code="MOTOR_GRADER_AND_ROLLER_OPERATION",
        name="Motor Grader and Roller Operation",
        trade_code="MACHINE_OPERATION",
        description=(
            "Grading and compacting subgrade and base course for roads and "
            "hardstanding using graders, rollers and compactors."
        ),
        display_order=540,
    ),
    SkillSeed(
        code="CONCRETE_MIXER_AND_PUMP_OPERATION",
        name="Concrete Mixer and Pump Operation",
        trade_code="MACHINE_OPERATION",
        description=(
            "Operating mixers and concrete pumps, managing batching, slump and the pour sequence."
        ),
        display_order=550,
    ),
    SkillSeed(
        code="FORKLIFT_AND_HOIST_OPERATION",
        name="Forklift and Hoist Operation",
        trade_code="MACHINE_OPERATION",
        description=(
            "Operating forklifts, hoists and man lifts for lifting and "
            "materials handling, including slinging and signalling."
        ),
        display_order=560,
    ),
    SkillSeed(
        code="PLANT_MAINTENANCE_AND_PRE_USE_CHECKS",
        name="Plant Maintenance and Pre-Use Checks",
        trade_code="MACHINE_OPERATION",
        description=(
            "Daily pre-use checks, greasing, minor servicing and defect "
            "reporting that keep plant on site running."
        ),
        display_order=570,
    ),
    # --- Quarry work ----------------------------------------------------------- #
    SkillSeed(
        code="CRUSHING_PLANT_OPERATION",
        name="Crushing Plant Operation",
        trade_code="QUARRY_WORK",
        description=(
            "Running jaw, cone and screen plants and feeding the crusher while "
            "watching for tramp metal and blockages."
        ),
        display_order=580,
    ),
    SkillSeed(
        code="AGGREGATE_STOCKPILING_AND_LOADING",
        name="Aggregate Stockpiling and Loading",
        trade_code="QUARRY_WORK",
        description=(
            "Managing stockpiles, controlling moisture and fragmentation, and "
            "loading trucks safely."
        ),
        display_order=590,
    ),
    # --- General labour -------------------------------------------------------- #
    SkillSeed(
        code="MANUAL_MIXING_AND_BARROW_RUNS",
        name="Manual Mixing and Barrow Runs",
        trade_code="GENERAL_LABOUR",
        description=(
            "Hand-mixing cement and mortar, barrowing material and water, and "
            "keeping supplies moving to the working face."
        ),
        display_order=600,
    ),
    SkillSeed(
        code="SITE_CLEANING_AND_WASTE",
        name="Site Cleaning and Waste",
        trade_code="GENERAL_LABOUR",
        description=(
            "Keeping the site clear and safe, segregating waste and managing tipping and spoil."
        ),
        display_order=610,
    ),
    # --- Landscaping ------------------------------------------------------------- #
    SkillSeed(
        code="SOIL_PREPARATION_AND_PLANTING",
        name="Soil Preparation and Planting",
        trade_code="LANDSCAPING",
        description=(
            "Preparing and conditioning soil, planting trees, shrubs and "
            "hedges, and staking them against wind."
        ),
        display_order=620,
    ),
    SkillSeed(
        code="TURF_LAIDING",
        name="Turf Laying",
        trade_code="LANDSCAPING",
        description=(
            "Laying and jointing instant turf and seeding new lawns, with "
            "correct levels and edging."
        ),
        display_order=630,
    ),
    SkillSeed(
        code="IRRIGATION_INSTALLATION",
        name="Irrigation Installation",
        trade_code="LANDSCAPING",
        description=(
            "Installing and commissioning drip and sprinkler irrigation, "
            "timers and water supplies for landscape works."
        ),
        display_order=640,
    ),
)


def _assert_skills_are_sound() -> None:
    """Resolve every ``trade_code`` against :data:`TRADES` at import time.

    A dangling trade code would otherwise become a skill with no trade, quietly
    breaking the "skills are grouped under a trade" assumption that the matching
    and admin screens depend on.
    """
    codes: set[str] = set()
    for skill in SKILLS:
        if not skill.code.strip() or not skill.name.strip() or not skill.description.strip():
            raise ValueError(f"Skill {skill.code!r} is missing a required field")
        if skill.code in codes:
            raise ValueError(f"Duplicate skill code {skill.code!r}")
        codes.add(skill.code)
        if skill.trade_code is not None and skill.trade_code not in TRADES_BY_CODE:
            raise ValueError(f"Skill {skill.code!r} references unknown trade {skill.trade_code!r}")


_assert_skills_are_sound()
