"""Parser for the event log: one physical line, one event, in fixed-width columns (README_event_log.md).

    from event_log_parser import ParserConfig, parse_line
    record = parse_line(line, line_number=1, source_file="Dec 25/x.log.gz", config=ParserConfig())
    record.parse_status      # parsed | parsed_with_warnings | unclassified | invalid | message
    record.to_dict()         # the fields, every raw representation, warnings and errors

Each line is LINE_WIDTH characters and every field has its own column (COLUMNS, measured on the sample of
2026-10-19). The prefix, date, time and triplet are cut at their positions, and the gaps between them must be blank.
From code 1 on, each word goes, whole, to the column it starts in: a word is never split, so a field that drifts a
little still lands in its column, and a word that starts in a gap between two columns is an exception. Each field is
then checked. On a reading, the identifier 3
column holds identifier 3, the unit and two right-aligned numbers (READING_COLUMNS); otherwise it is identifier 3
alone. An identifier 3 that is not in its list and is all lowercase is a user's name: it is kept as user_name, not
as identifier 3; so is an all-lowercase word where the limit code belongs, and when the two differ, the limit code's is
the user's name and identifier 3's stays identifier 3. A state is stored in upper case, however it is written. A state
written where the limit code belongs means the line has no limit code. A line that is only the text of an ANOMALY_LINES entry is not read: it is an
exception under that entry's own code. A line with GONG APPEAR TONE after its date and time is a message whose alarm
type, counts and user name are read (GONG_MESSAGE). After a line is parsed, an identifier 3 of IDENTIFIER_3_STATES
moves to the state (postprocessing). The original line is kept as it was.

The format answers of 2026-10-19 are built in (README_event_log.md, 'Format decisions'). The lists of known codes
and identifiers are below, to be filled in by hand.
"""
from __future__ import annotations

import json
import operator
import re
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import cached_property, lru_cache
from pathlib import Path

# --- Values you maintain: fill in the codes and identifiers here ---------------------------------------------------
# One string per value, e.g.  IDENTIFIER_3_VALUES = ["FAN 4", "PUMP 12 NORTH"]
# Matching is exact and case-sensitive, like a password: "Fan 4" or "FAN  4" (two spaces) do not match "FAN 4".
# No message, log or summary prints these lists; the summary shows only how many values each holds.
# A line whose code 1, identifier 1 or identifier 3 is not listed yet is 'unclassified' (kept, not an error); each run
# writes event_log_unclassified_values.csv with the values to add next, the most lines first.
# An identifier 3 is also classified when it contains a keyword of IDENTIFIER_3_KEYWORDS (below its list).
# An identifier 3 that is not listed and is all lowercase is a user's name (user_name), not a value to add; so is an
# all-lowercase word where the limit code belongs. When the two differ, the limit code's is the user's name, and
# identifier 3's stays identifier 3 (unclassified until listed).
# Code 2 and identifier 2 are not listed: any value of the right characters is accepted, or a blank. An identifier 2
# with another character is accepted only when it is in IDENTIFIER_2_WITH_SYMBOLS.
# Grouped by assumed function, for reading only: neither the groups nor the order affect matching.
CODE_1_VALUES: list[str] = [
    # Power
    "PSS", "POW", "PWR",
    # HVAC / Ventilation
    "ECS",
    # Stations / Depots
    "BSH", "NEW", "RDH", "YCK",
    # Others
    "DEC", "ETC", "SCS",
    # Not grouped yet (added 2026-10-19)
    "DECAMS", "ETS", "ECD", "HFD", "TNM", "BDI", "SBO", "BDL", "CKO", "SFI", "SIM", "EUN", "JPO", "TAP", "TWD", "XPO",
    "YWT", "BNV", "PYL", "SRO", "OCC",
]

IDENTIFIER_1_VALUES: list[str] = [
    # Power: 22 kV
    "22KV", "22KV_EW", "22KV_NS", "22KV_LC2", "22KV_TDI",
    # Power: 750 V DC traction
    "750V", "750V_EW", "750V_NS", "750V_ESS", "750V_LC2", "750V_MWS", "750V_SS",
    "KBTSS", "ETS", "ETTS", "ETTS_EW",
    # Power: other
    "MV_U", "AUX", "VARPW",
    # HVAC / Ventilation
    "ECS", "FAN",
    # Fire / Smoke
    "FAS", "FSH",
    # Water / Pumps
    "PMP", "WP", "WPEE", "WPNE", "WPSE", "WPWE",
    # SCADA / Communications
    "POW_RTU", "POW_RTU1", "POW_RTU2",
    "RTU06", "RTU11", "RTU46", "RTU52", "RTU52_A", "RTU69", "RTU72", "RTU76", "RTU77",
    "COM", "MIMIC",
    # Operations / Control
    "MODE",
    # Railway Operations
    "TRAIN",
    # Others
    "MP1", "MP1EW", "MP1NS", "MP2", "MSP", "ENL", "TR", "DUMMY",
    # Others: the AP family, plain then by end (EE, NE, SE, WE)
    "AP", "APAL", "APB", "APC", "APG", "APIP", "APM", "APMG", "APP", "APPC", "APTH", "APTS",
    "APEE", "APEEAL", "APEEB", "APEEC", "APEEM", "APEEP",
    "APNE", "APNEC", "APNEM", "APNEP",
    "APSE", "APSEB", "APSEC", "APSEM", "APSEP", "APSEPL",
    "APWE", "APWEB", "APWEC", "APWEG", "APWEM", "APWEP",
]

# Identifier 2 values accepted although they have a character other than letters, digits, _ and - (exact). For now,
# 2026-10-19: we learn as we go.
IDENTIFIER_2_WITH_SYMBOLS: list[str] = [
    "FA_Z6&7",
]

IDENTIFIER_3_VALUES: list[str] = [
    # Power: traction (750 V DC, third rail)
    "3rd Rail Live",
    "3rd Rail Live 1",
    "3rd Rail Live 2",
    "3rd Rail Live Fault",
    "3rd Rail Undervoltage",
    "Rail Section Power",
    "750VDC Busbar Live",
    "750VDC Backup Live",
    "750VDC Outgoing Live",
    "Mainline 750VDC live",
    "Depot 750VDC live",
    "DC Rectifier Fault",
    "GRC (Traction On)",
    "GRC (Traction Off)",
    "GRC (64P)",
    "TSS OR First Level",

    # Power: traction sections live -- any value with "Live" (IDENTIFIER_3_KEYWORDS)

    # Power: feeders and busbars
    "Feeder Cable Live",
    "Feeder Undervoltage",
    "Outgoing Live",
    "Busbar Undervoltage",
    "Transfer Cable Fault",

    # Power: supply
    "Power",
    "Power Status",
    "Power Supply Status",
    "Control Source Fault",
    "SWGR Control Source Fault",

    # Power: transformers
    "Oil Level Alarm",
    "Oil Temperature Alarm",
    "Temperature Level1 Crossed",
    "Temperature Level2 Crossed",
    "Pressure Rise Fault",
    "Pressure Relief Fault",

    # Power: UPS, battery, charger
    "Inverter Ready",
    "On Battery",
    "UPS Summary Alarm",
    "AC UPS System Fault",
    "Charger Summary Alarm",
    "Charger Fault",

    # Switchgear: circuit breaker position
    "CB Position",
    "CB Service Position",
    "At Test Position",
    "Test or Disconnect Position",
    "CB DS On Position",
    "CB ES On Position",
    "CB DS&ES Off Position",
    "MV_CBI",
    "MV_U",                                           # moves to the state after parsing (IDENTIFIER_3_STATES)
    "MV-PF",                                          # moves to the state after parsing (IDENTIFIER_3_STATES)
    "Selector Switch",

    # Switchgear: trips and protection
    "CB Trip",
    "CB Lockout Trip",
    "CB Overload",
    "CB At Reclosing",
    "CB At Reclosing Fault",
    "CB Ctrl-Inh",
    "Emergency Trip",
    "Transfer Trip Bypass Ctrl-Inh",

    # Switchgear: contactors -- any value with "Contactor Energise" (IDENTIFIER_3_KEYWORDS)

    # HVAC: chiller plant
    "Water Cooled Chiller Status",
    "Water Cooled Chiller Alarm",
    "Chilled Water Pump Status",
    "Condenser Water Pump Status",
    "Makeup Water Pump Status",
    "Cooling Tower Status",

    # HVAC: air handling and package units
    "Air Handling Unit Status",
    "Air Handling Unit Alarm",
    "Fan Coil Unit Status",
    "Package Condenser Unit Status",
    "Package Evaporate Unit Status",
    "Package Evaporation Unit Status",
    "Package Evaporate Unit Alarm",
    "PEU Alarm Free Note",
    "Supply Air Flow Status",
    "Return Air Status",
    "Return Air Flow Status",
    "Return Air Fault",
    "Return Airflow Alarm",

    # HVAC: station fans
    "INF001",
    "Intake Fan Status",
    "Intake Fan Alarm",
    "Intake Fan Alarm Free Note",
    "Intake Airflow Alarm",
    "EXF002",
    "Exhaust Fan Status",
    "Exhaust Fan Alarm",
    "Exhaust Fan Alarm Free Note",
    "Exhaust Airflow Alarm",
    "Fan Summary Alarm",

    # HVAC: tunnel and under-platform ventilation
    "Tunnel Vent Intake Fan Status",
    "Tunnel Vent Exhaust Fan Status",
    "Tunnel Vent Intake/Exhaust Fan",
    "Tunnel Vent Fan Alarm",
    "Tunnel Vent Fan Ala Free Note",
    "Tunnel Vent Fan Stoplock",
    "UnderPlatform Exh Fan Status",
    "UnderPlatform Exh Fan Summ Sta",
    "UnderPlatform Exh Fan Alarm",
    "UnderPlatform Exh F Free Note",
    "Vent Ctrl Panel Mode",

    # HVAC: dampers
    "Damper Status",
    "Damper Status Free Note",
    "Damper Alarm",

    # HVAC: temperature and humidity
    "TEMP",
    "Humid",
    "HUMID",                                          # moves to the state after parsing (IDENTIFIER_3_STATES)
    "High Temperature",

    # Fire / Smoke
    "Station Fire Alarm",
    "Dpt Int Onl Fire Alm",
    "Fire Light & Buzzer",
    "Fire Reset",
    "Fire Shutter Position",
    "Fire Shutter Alm",
    "Smoke Extract Fan Status",
    "Smoke Extract Fan Alarm",
    "Smoke Control Panel Mode",

    # Water / Pumps
    "Pump Status",
    "COML WP Summary Status",
    "Tank High Level Al",
    "SMP High Level Alarm",
    "High Level Crossed",
    "Low Level Alarm",

    # SCADA / Communications
    "ECS Link Fault",
    "RTU-HMI Link Fault",
    "SDH Equipment Fault",
    "FO Module 2 Sum Flt",
    "I/O Module 2 Sum Flt",
    "I/O Cards Discrepancy",
    "time sync command",                              # all lowercase, but listed: identifier 3, not a user's name
    "RTU Door Contact",
    "Marshalling Door Contact",

    # Operations / Control
    "Operation Mode",
    "Operation Status",
    "Ok To Operate",
    "Local Control Panel Mode",
    "Test Mode",
    "Maintenance",
    "Direction",
    "Position",
    "Position Free Note",
    "Alarm Reset",
    "General Reset",
    "Summary Fault Reset Ctrl-Inh",

    # Fault / Monitoring
    "Summary Alarm",
    "Summary Fault",
    "Common Fault",
    "Equipment Fault",
    "Control Panel Fault & Alarm",
    "Trip",
    "Trip Indication",
    "Condition Monitoring Sum",
    "Condition Monitoring Sum AL",
    "Partial Discharge CM Summ Al",
    "LRU General Check running",
    "device failure",                                 # all lowercase, but listed: identifier 3, not a user's name
    "device locked",                                  # all lowercase, but listed: identifier 3, not a user's name

    # Railway Operations
    "Train Stop",
    "Train Stop Isolated",

    # Others
    "Bypass State",
    "Cash Trolley Operation",
    "Config",
    "FLOWM",
    "Low Pressure Alarm",
]

# An identifier 3 that contains one of these anywhere (exact case) is classified as if listed: the many numbered
# points of one kind, such as "E12Contactor Energise" or "E27_E28 Live", need no entry of their own.
IDENTIFIER_3_KEYWORDS: list[str] = [
    "Contactor Energise",                             # Switchgear: contactors
    "Live",                                           # Power: traction sections live
]

# Identifier 3 values that are states. Postprocessing, once a line is parsed: such a value moves from identifier 3 to
# the state, replacing any state the line had, and identifier 3 is left blank (your answers, 2026-10-21). Each is in
# IDENTIFIER_3_VALUES too, so the line is classified first. Exact, like the lists; the summary shows only a count.
IDENTIFIER_3_STATES: list[str] = ["MV_U", "HUMID", "MV-PF"]
PREFIXES = {"A": 0, "G": 1}                           # each prefix and its position (G: against the date); A, G, AG or none
UNITS = ("A", "DEGC", "V", "%", "L/S", "KV")
NO_UNIT = ("-",)                                      # written in the unit column of a reading that has no unit
NO_VALUE = ("****.*",)                                # written in a number column of a reading that has no value
STATES = ("APP", "DISP", "STOP", "ON", "NO", "RUN", "OFF", "CLOSE", "OPEN", "YES", "LOCAL", "REMOTE", "UP", "DOWN", "START",
          "OK", "FAULT", "COMPLETE", "UNTAG", "INCONSIS", "REVERSE", "FORWARD", "LOGON", "LOGOFF", "TAG", "ONLINE", "OFFLINE",
          "NOTCON", "EMPTY", "ACTIVE", "RUNUP", "UNREACH", "DEGRADED", "END", "PRI", "SEC", "SPAD", "ADM", "STDBY", "COM", "TC",
          "RELEASED", "FAULTY", "LOCKED", "MANUAL", "AUTO", "POWCON", "PARALLEL", "FALSE", "TRUE", "INDIVIDU", "RESTORE",
          "01", "02", "03", "04", "05", "06",
          "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "LEVEL2", "ADSP", "MMI", "SCBKWH", "NOTREADY", "NO SOURC", "NOT SYNC", "SLAVE", "MASTER",
          "DISTURBE")
# Other ways a state is written, and the state each means (exact case). Every state is stored in upper case.
# REMARK, 2026-10-19: what the lowercase c before POWCON and SCBKWH means is not known yet; each is read without it for
# now. To find out.
STATE_SPELLINGS = {"cPOWCON": "POWCON", "cSCBKWH": "SCBKWH"}
LIMIT_CODES = ("L1", "U1", "L2", "U2", "WE", "MU", "NT", "AL", "NE", "W*")   # any text may follow the code (limit_suffix)
MESSAGE_PREFIXES = ("Command Failure :",)            # a line whose text begins with one is a system message, not an event
# A line with GONG APPEAR TONE after its date and time is a message with fields, in one of two forms, any whitespace
# between the words (your answers, 2026-10-21):
#   GONG APPEAR TONE ALMTYPE<0 to 7> O: <count> N: <count> <user name>
#   GONG APPEAR TONE SYSTEM <user name>
GONG_MARK = re.compile(r"GONG\s+APPEAR\s+TONE")
GONG_MESSAGE = re.compile(r"GONG\s+APPEAR\s+TONE\s+(?:(ALMTYPE[0-7])\s+O:\s*(\d+)\s+N:\s*(\d+)|(SYSTEM))\s+(\S+)\s*")
# A line whose whole text (blanks at either end aside) is one of these is an anomaly of its own: no field is read, and it
# goes to the exceptions file under its code alone. Exact and case-sensitive; the summary shows only how many there are.
ANOMALY_LINES = {"I'm dyn028": "IM_LINE"}
# The groups of states that belong together (ON/OFF; Transformer: 01 to 20) are STATE_GROUPS in event_log_devices.py: they classify
# devices, never a line.
LINE_WIDTH = 132
# Where each field sits: [start, end) character positions from 0, measured on the sample of 2026-10-19; the prefix
# column takes in position 1 for G (your answer, 2026-10-19). Up to code 1,
# the positions between columns must be blank. From code 1 on, a word belongs to the column it starts in and may run
# on past it, but may not start between two columns. Identifier 2 is one word: any more words that start in its column
# begin the location early ("TSS BGS-LVR": TSS, BGS-LVR; "TSS MRB": TSS, MRB; "LSC01 TVS OCC": LSC01, TVS OCC).
# Nothing separates identifier 2 from the location, so a word running past identifier 2's column is cut at 55.
COLUMNS = {"prefix": (0, 2), "date": (2, 10), "time": (11, 19), "numeric_triplet": (20, 28), "code_1": (29, 32),
           "code_2": (33, 36), "identifier_1": (37, 45), "identifier_2": (46, 55), "location": (55, 75),
           "identifier_3": (76, 106), "state": (107, 115), "limit_code": (116, 132)}     # the limit code and any text after it, to the end of the line
# On a reading, the identifier 3 column holds identifier 3, the unit and two right-aligned numbers
READING_COLUMNS = {"identifier_3": (76, 85), "unit_or_type": (85, 89), "number_1": (89, 96), "number_2": (96, 103)}
OPTIONAL_FIELDS = ("numeric_triplet", "code_1", "code_2", "identifier_1", "identifier_2", "location", "identifier_3",
                   "unit_or_type", "number_1", "number_2", "state", "limit_code")
                                                      # may be blank; the rest are required
# A line is classified when each of these is in its list above; until then it is 'unclassified' (not an error)
CLASSIFICATION_FIELDS = ("code_1", "identifier_1", "identifier_3")
LIST_NAMES = {"code_1": "CODE_1_VALUES", "identifier_1": "IDENTIFIER_1_VALUES", "identifier_3": "IDENTIFIER_3_VALUES",
              "code_2": "code_2_values", "identifier_2": "identifier_2_values"}

PARSED, PARSED_WITH_WARNINGS, UNCLASSIFIED, INVALID = "parsed", "parsed_with_warnings", "unclassified", "invalid"
MESSAGE = "message"                                   # a system message line ('Command Failure : ...'), not an event
BOM = "﻿"

_DATE = re.compile(r"\d{2}/\d{2}/\d{2}")
_TIME = re.compile(r"\d{2}:\d{2}:\d{2}")
_SPACE = re.compile(r"\s+")
_INTEGER = re.compile(r"-?\d+")
_ALPHANUMERIC = re.compile(r"[A-Za-z0-9]+")
_WORD = re.compile(r"\S+")
_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
_OFFSET = re.compile(r"([+-])(\d{2}):(\d{2})")
_CODE = re.compile(r"[A-Z][A-Z0-9_]*")
_TRIPLET_PART = re.compile(r" *\d+")


@lru_cache(maxsize=64)
def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern)


# --- configuration --------------------------------------------------------------------------------------------------

def _columns(value) -> dict:
    return {name: tuple(span) for name, span in dict(value).items()}


@dataclass(frozen=True)
class ParserConfig:
    """The format as measured and answered on 2026-10-19 (README_event_log.md)."""
    line_width: int = LINE_WIDTH
    columns: dict = field(default_factory=lambda: dict(COLUMNS))
    reading_columns: dict = field(default_factory=lambda: dict(READING_COLUMNS))
    code_1_pattern: str = r"[A-Z]{2,6}"               # code 1: two to six uppercase letters
    code_2_pattern: str = r"[A-Z]{2,6}"               # code 2: two to six uppercase letters
    identifier_pattern: str = r"[A-Za-z0-9_-]+"       # identifiers 1 and 2: letters, digits, _ and -
    identifier_3_pattern: str = r"[A-Za-z0-9*()_/&.-]+(?: +[A-Za-z0-9*()_/&.-]+)*"   # and spaces between words
    code_1_values: tuple = tuple(CODE_1_VALUES)       # the lists above
    code_2_values: tuple = ()                         # not listed: any three uppercase letters (a list may come from --config)
    identifier_1_values: tuple = tuple(IDENTIFIER_1_VALUES)
    identifier_2_values: tuple = ()                   # not listed: any value of the right characters
    identifier_2_with_symbols: tuple = tuple(IDENTIFIER_2_WITH_SYMBOLS)   # accepted despite a symbol
    identifier_3_values: tuple = tuple(IDENTIFIER_3_VALUES)
    identifier_3_keywords: tuple = tuple(IDENTIFIER_3_KEYWORDS)   # an identifier 3 containing one is classified
    identifier_3_states: tuple = tuple(IDENTIFIER_3_STATES)       # moved to the state after parsing
    classification_fields: tuple = CLASSIFICATION_FIELDS   # a line is classified once each of these is in its list
    allowed_units: tuple = UNITS
    no_unit_markers: tuple = NO_UNIT                  # a reading whose unit column holds one of these has no unit
    no_value_markers: tuple = NO_VALUE                # a reading's number column holding one of these has no value
    allowed_states: tuple = STATES
    state_spellings: dict = field(default_factory=lambda: dict(STATE_SPELLINGS))   # cPOWCON: POWCON
    allowed_limit_codes: tuple = LIMIT_CODES
    optional_fields: tuple = OPTIONAL_FIELDS          # fields that may be blank
    number_pattern: str = r"-?\d+(?:\.\d+)?"          # a minus sign if any, never a plus; decimals kept exact
    century: int | None = 2000                        # two-digit years are 20xx
    utc_offset: str = "+08:00"                        # the clock the times are written in (24-hour)
    expected_month: str | None = None                 # YYYY-MM: the folder's month; a line from another month is flagged
    message_prefixes: tuple = MESSAGE_PREFIXES        # a line whose text begins with one is a system message
    anomaly_lines: dict = field(default_factory=lambda: dict(ANOMALY_LINES))   # a line of only this text: its own code
    strict_mode: bool = False                         # lenient: unknown units, states, limit codes kept with warnings

    def __post_init__(self):
        object.__setattr__(self, "columns", _columns(self.columns))
        object.__setattr__(self, "reading_columns", _columns(self.reading_columns))
        object.__setattr__(self, "anomaly_lines", dict(self.anomaly_lines))
        object.__setattr__(self, "state_spellings", dict(self.state_spellings))
        if set(self.columns) != set(COLUMNS):
            raise ValueError(f"columns must name exactly: {', '.join(COLUMNS)}.")
        if set(self.reading_columns) != set(READING_COLUMNS):
            raise ValueError(f"reading_columns must name exactly: {', '.join(READING_COLUMNS)}.")
        spans = sorted(self.columns.values())
        if any(not (0 <= a < b <= self.line_width) for a, b in spans) or any(b > c for (_, b), (c, _) in zip(spans, spans[1:])):
            raise ValueError("columns must be [start, end) spans inside the line width that do not overlap.")
        r0, r1 = self.columns["identifier_3"]
        if any(not (r0 <= a < b <= r1) for a, b in self.reading_columns.values()):
            raise ValueError("reading_columns must lie inside the identifier_3 column.")
        width = self.columns["numeric_triplet"][1] - self.columns["numeric_triplet"][0]
        if width < 5 or (width - 2) % 3:
            raise ValueError("the numeric_triplet column must be 3 equal parts and 2 slashes wide, such as 8.")
        if self.century is not None and (not isinstance(self.century, int) or self.century % 100):
            raise ValueError("century must be a multiple of 100, such as 2000, or null.")
        if not _OFFSET.fullmatch(self.utc_offset or ""):
            raise ValueError("utc_offset must look like +08:00.")
        if self.expected_month is not None and not re.fullmatch(r"\d{4}-\d{2}", self.expected_month):
            raise ValueError("expected_month must look like 2026-10.")
        if any(not isinstance(v, str) or not v or any(c.isspace() for c in v) for v in self.identifier_2_with_symbols):
            raise ValueError("identifier_2_with_symbols must be single words, none of them blank.")
        if any(not isinstance(k, str) or not k.strip() for k in self.identifier_3_keywords):
            raise ValueError("identifier_3_keywords must be text, none of it blank (a blank keyword would match anything).")
        if any(not isinstance(p, str) or not p.strip() for p in self.message_prefixes):
            raise ValueError("message_prefixes must be text, none of it blank (a blank prefix would match every line).")
        if any(not isinstance(text, str) or not text.strip() or text != text.strip() or not isinstance(code, str)
               or not _CODE.fullmatch(code) for text, code in self.anomaly_lines.items()):
            raise ValueError("anomaly_lines must map text, not blank and with no blanks at either end, to a code of "
                             "uppercase letters, digits and _, such as IM_LINE.")
        if any(not isinstance(text, str) or not text.strip() or not isinstance(state, str) or not state.strip()
               or state != state.upper() for text, state in self.state_spellings.items()):
            raise ValueError("state_spellings must map text, not blank, to a state in upper case, such as cPOWCON to POWCON.")
        if set(self.classification_fields) - set(LIST_NAMES):
            raise ValueError(f"classification_fields may only name {', '.join(LIST_NAMES)}.")
        unknown = set(self.optional_fields) - set(FIELD_NAMES)
        if unknown:
            raise ValueError(f"optional_fields names unknown fields: {', '.join(sorted(unknown))}.")
        for name in ("code_1_pattern", "code_2_pattern", "identifier_pattern", "identifier_3_pattern", "number_pattern"):
            try:
                _rx(getattr(self, name))                # a bad pattern fails here, not on the first line
            except re.error as error:
                raise ValueError(f"{name} is not a valid regular expression: {error}.") from None

    @classmethod
    def from_dict(cls, data: dict) -> "ParserConfig":
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"Unknown parser settings: {', '.join(unknown)}.")
        values = {}
        for key, value in data.items():
            if isinstance(value, list):
                value = tuple(value)
            values[key] = value
        return cls(**values)

    @classmethod
    def from_file(cls, path: str | Path) -> "ParserConfig":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict:
        def plain(key, value):
            if key in ("columns", "reading_columns"):
                return {name: list(span) for name, span in value.items()}
            return list(value) if isinstance(value, tuple) else value
        return {f.name: plain(f.name, getattr(self, f.name)) for f in fields(self)}

    def to_public_dict(self) -> dict:
        """to_dict() for summaries and logs: the identifier lists, kept like passwords, as counts only."""
        out = self.to_dict()
        for key in SECRET_SETTINGS:
            out[key] = f"{len(out[key])} values (not shown)"
        return out

    @property
    def tz(self) -> timezone:
        return _tz(self.utc_offset)

    @cached_property
    def lookups(self) -> "_Lookups":
        """What every line looks up, built once for these settings (_Lookups)."""
        return _Lookups(self)


SECRET_SETTINGS = ("identifier_1_values", "identifier_2_values", "identifier_2_with_symbols", "identifier_3_values",
                   "identifier_3_keywords", "identifier_3_states", "anomaly_lines")
FIELD_NAMES = ("prefix", "date", "time", "numeric_triplet", "code_1", "code_2", "identifier_1", "identifier_2", "location",
               "identifier_3", "unit_or_type", "number_1", "number_2", "state", "limit_code")
DEFAULT_CONFIG = ParserConfig()


class _Lookups:
    """What every line looks up, built once per configuration rather than per line: hash sets for the lists (O(1)
    membership instead of a scan of up to ~160 values), the column each position belongs to (a direct-address table
    instead of a search of the columns), the gap positions before code 1 (four, not all 29 positions), the limit codes
    longest first (sorted once), the keywords as one regular expression, and the compiled patterns."""

    def __init__(self, cfg: ParserConfig):
        cols = cfg.columns
        self.body = cols["code_1"][0]
        self.head = sorted((span, name) for name, span in cols.items() if span[0] < self.body)
        covered = {i for (a, b), _ in self.head for i in range(a, b)}
        self.gap_list = [i for i in range(self.body) if i not in covered]
        self.gaps = frozenset(self.gap_list)
        self.columns = sorted((span, name) for name, span in cols.items() if span[0] >= self.body)
        self.names = [name for _, name in self.columns]
        self.owner: list[str | None] = [None] * cfg.line_width
        for (a, b), name in self.columns:
            self.owner[a:min(b, cfg.line_width)] = [name] * (min(b, cfg.line_width) - a)
        self.values = {name: frozenset(getattr(cfg, f"{name}_values")) for name in LIST_NAMES}
        self.states = frozenset(cfg.allowed_states)
        self.units = frozenset(cfg.allowed_units)
        self.no_unit, self.no_value = frozenset(cfg.no_unit_markers), frozenset(cfg.no_value_markers)
        self.with_symbols, self.to_state = frozenset(cfg.identifier_2_with_symbols), frozenset(cfg.identifier_3_states)
        self.optional, self.classification = frozenset(cfg.optional_fields), frozenset(cfg.classification_fields)
        self.limit_codes = tuple(sorted(cfg.allowed_limit_codes, key=len, reverse=True))
        self.prefixes = tuple(cfg.message_prefixes)
        keywords = sorted(cfg.identifier_3_keywords, key=len, reverse=True)
        self.keywords = re.compile("|".join(map(re.escape, keywords))) if keywords else None
        self.patterns = {name: re.compile(getattr(cfg, f"{name}_pattern"))
                         for name in ("code_1", "code_2", "identifier", "identifier_3", "number")}


# --- the data model -------------------------------------------------------------------------------------------------

@dataclass
class Issue:
    """A warning or an error: what, where (character offsets into raw_line, end exclusive) and the value found."""
    code: str
    message: str
    field: str | None = None
    value: str | None = None
    start_offset: int | None = None
    end_offset: int | None = None

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "field": self.field, "value": self.value,
                "start_offset": self.start_offset, "end_offset": self.end_offset}


@dataclass
class EventRecord:
    raw_line: str
    line_number: int | None = None
    source_file: str | None = None
    parse_status: str = INVALID
    prefix: str | None = None
    prefix_raw: str | None = None
    date_raw: str | None = None
    date_day: int | None = None
    date_month: int | None = None
    date_year_2digit: int | None = None
    date_iso: str | None = None                       # with the century (20xx)
    time_raw: str | None = None
    time_hour: int | None = None
    time_minute: int | None = None
    time_second: int | None = None
    timestamp: str | None = None                      # ISO 8601 with the log's UTC offset: 2026-10-19T14:35:02+08:00
    timestamp_utc: str | None = None                  # the same moment in UTC: 2026-10-19T06:35:02Z
    numeric_triplet_raw: str | None = None
    triplet_first: int | None = None
    triplet_second: int | None = None
    triplet_third: int | None = None
    code_1: str | None = None
    code_2: str | None = None
    identifier_1: str | None = None
    identifier_2: str | None = None
    location_raw: str | None = None
    location: str | None = None
    location_normalized: str | None = None
    identifier_3: str | None = None
    user_name: str | None = None                      # a user's name (all lowercase) in identifier 3's or the limit code's column
    is_reading: bool = False                         # identifier 3 followed by a unit and two numbers
    unit_raw: str | None = None                       # the unit column as written ('-' included)
    unit_or_type: str | None = None
    number_1_raw: str | None = None
    number_1: int | Decimal | None = None
    number_2_raw: str | None = None
    number_2: int | Decimal | None = None
    state: str | None = None
    limit_code: str | None = None
    limit_suffix: str | None = None                   # any text after the limit code
    message: str | None = None                        # a system message line's text, spaces collapsed (status 'message')
    alarm_type: str | None = None                     # a GONG APPEAR TONE message: its alarm type (ALMTYPE0-7, SYSTEM)
    o_count: int | None = None                        # its O: count (ALMTYPE0-7 only)
    n_count: int | None = None                        # its N: count (ALMTYPE0-7 only)
    unclassified_fields: list = field(default_factory=list)  # classification fields not in their lists yet
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """The record in the specification's shape: date, time and triplet nested, decimals as JSON numbers."""
        both = lambda *values: None if all(v is None for v in values) else values      # noqa: E731
        date, time_, triplet = (both(self.date_day, self.date_month, self.date_year_2digit),
                                both(self.time_hour, self.time_minute, self.time_second),
                                both(self.triplet_first, self.triplet_second, self.triplet_third))
        return {
            "parse_status": self.parse_status, "line_number": self.line_number, "source_file": self.source_file,
            "raw_line": self.raw_line, "prefix": self.prefix, "prefix_raw": self.prefix_raw,
            "date_raw": self.date_raw,
            "date": dict(zip(("day", "month", "year_2digit"), date)) if date else None, "date_iso": self.date_iso,
            "time_raw": self.time_raw, "time": dict(zip(("hour", "minute", "second"), time_)) if time_ else None,
            "timestamp": self.timestamp, "timestamp_utc": self.timestamp_utc,
            "numeric_triplet_raw": self.numeric_triplet_raw,
            "numeric_triplet": dict(zip(("first", "second", "third"), triplet)) if triplet else None,
            "code_1": self.code_1, "code_2": self.code_2, "identifier_1": self.identifier_1, "identifier_2": self.identifier_2,
            "location_raw": self.location_raw, "location": self.location, "location_normalized": self.location_normalized,
            "identifier_3": self.identifier_3, "user_name": self.user_name, "is_reading": self.is_reading, "unit_raw": self.unit_raw,
            "unit_or_type": self.unit_or_type,
            "number_1_raw": self.number_1_raw, "number_1": _json_number(self.number_1),
            "number_2_raw": self.number_2_raw, "number_2": _json_number(self.number_2),
            "state": self.state, "limit_code": self.limit_code, "limit_suffix": self.limit_suffix, "message": self.message,
            "alarm_type": self.alarm_type, "o_count": self.o_count, "n_count": self.n_count,
            "unclassified_fields": list(self.unclassified_fields),
            "warnings": [w.to_dict() for w in self.warnings], "errors": [e.to_dict() for e in self.errors],
        }

    def to_row(self) -> dict:
        """One flat row (CSV): every field, numbers as their exact text, lists joined by ';'."""
        return dict(zip(ROW_FIELDS, self.to_values()))

    def to_values(self) -> list:
        """to_row()'s values as a list in ROW_FIELDS order, read with one attrgetter: what the events CSV writes."""
        row = list(_GET_PLAIN(self))
        row[_NUMBER_1] = None if self.number_1 is None else str(self.number_1)
        row[_NUMBER_2] = None if self.number_2 is None else str(self.number_2)
        row[_UNCLASSIFIED] = ";".join(self.unclassified_fields)
        row.append(";".join(w.code for w in self.warnings))
        row.append(";".join(e.code for e in self.errors))
        return row


ROW_FIELDS = [f.name for f in fields(EventRecord) if f.name not in ("warnings", "errors")] + ["warning_codes", "error_codes"]
_GET_PLAIN = operator.attrgetter(*ROW_FIELDS[:-2])
_NUMBER_1, _NUMBER_2, _UNCLASSIFIED = (ROW_FIELDS.index(name) for name in ("number_1", "number_2", "unclassified_fields"))


def _json_number(value):
    """Decimals become JSON numbers (the exact text stays in the *_raw field); integers stay integers."""
    return float(value) if isinstance(value, Decimal) else value


# --- parsing --------------------------------------------------------------------------------------------------------

def parse_line(line: str, line_number: int | None = None, source_file: str | None = None,
               config: ParserConfig = DEFAULT_CONFIG) -> EventRecord:
    """One physical line -> one record. Only the line ending (\\r, \\n) is removed before parsing."""
    text = line.rstrip("\r\n")
    record = EventRecord(raw_line=text, line_number=line_number, source_file=source_file)
    _Line(text, config, record).parse()
    to_state(record, config)                                  # postprocessing
    record.parse_status = (INVALID if record.errors else MESSAGE if record.message is not None
                           else UNCLASSIFIED if record.unclassified_fields else PARSED_WITH_WARNINGS if record.warnings else PARSED)
    return record


def to_state(record: EventRecord, config: ParserConfig = DEFAULT_CONFIG) -> None:
    """Postprocessing, once a line is parsed: an identifier 3 of IDENTIFIER_3_STATES moves to the state, replacing any
    state the line had (the line keeps it in raw_line), and identifier 3 is left blank."""
    if record.identifier_3 is not None and record.identifier_3 in config.lookups.to_state:
        record.state, record.identifier_3 = record.identifier_3, None


@lru_cache(maxsize=64)
def _choices(values: tuple) -> str:
    values = list(values)
    if len(values) < 2:
        return "".join(values)
    return ", ".join(values[:-1]) + (", or " if len(values) > 2 else " or ") + values[-1]


class _Line:
    def __init__(self, text: str, config: ParserConfig, record: EventRecord):
        self.config, self.record, self.look = config, record, config.lookups
        self.base = 1 if text.startswith(BOM) else 0     # offsets stay offsets into raw_line
        self.text = text[self.base:]
        self.line = self.text.ljust(config.line_width)
        self.name_at = None                             # where identifier 3's column held a user's name
        self.fields: dict = {}                          # field() results: each column is cut once per line

    # issues ---------------------------------------------------------------------------------------------------------
    def _issue(self, target, code, message, field_name, value, start, end):
        target.append(Issue(code, message, field_name, value,
                            None if start is None else start + self.base, None if end is None else end + self.base))

    def error(self, code, message, field_name=None, value=None, start=None, end=None):
        self._issue(self.record.errors, code, message, field_name, value, start, end)

    def warn(self, code, message, field_name=None, value=None, start=None, end=None):
        self._issue(self.record.warnings, code, message, field_name, value, start, end)

    def unknown(self, attr, suffix, label, value, allowed, start, end) -> bool:
        """A value outside a closed or listed set. Lenient: kept, with a warning (True); strict: an error (False).
        An identifier list is never named in the message (kept like passwords)."""
        expected = f"in its list ({LIST_NAMES.get(attr, attr)})" if attr.startswith("identifier") else f"one of {_choices(allowed)}"
        if self.config.strict_mode:
            self.error(f"INVALID_{suffix}", f"{label} is not {expected}.", attr, value, start, end)
            return False
        self.warn(f"UNKNOWN_{suffix}", f"{label} is not {expected}; kept as found.", attr, value, start, end)
        return True

    def listed(self, attr, label, value, start, end, keywords=False):
        """Set attr. A classification field (code 1, identifiers 1 and 3) outside its list, and containing none of its
        keywords (identifier 3), leaves the line unclassified; any other field outside a filled list goes to unknown().
        Matching is exact and case-sensitive (a hash-set lookup), and an identifier list is never named in a message."""
        allowed = getattr(self.config, f"{attr}_values")                  # in order, for the messages
        search = self.look.keywords if keywords else None
        known = value in self.look.values[attr] or (search is not None and search.search(value) is not None)
        if attr in self.look.classification:
            setattr(self.record, attr, value)
            if not known:
                name = LIST_NAMES[attr]
                self.unclassified(attr, value, start, end,
                                  f"{label} is not in {name} yet" if allowed or search is not None else f"{name} is empty")
        elif not (allowed or search is not None) or known or self.unknown(attr, attr.upper(), label, value, allowed, start, end):
            setattr(self.record, attr, value)

    def unclassified(self, attr, value, start, end, why):
        """A value not in its list yet: the line is 'unclassified' (not an error) until the value is added."""
        self.record.unclassified_fields.append(attr)
        self.warn(f"UNCLASSIFIED_{attr.upper()}", f"{why}; the line stays unclassified until it is added.", attr, value, start, end)

    def optional(self, name) -> bool:
        return name in self.look.optional

    def cut(self, span):
        """(raw text of the span, its trimmed value, offsets of the value)."""
        a, b = span
        raw = self.line[a:b]
        value = raw.strip()
        start = a + len(raw) - len(raw.lstrip())
        return raw, value, (start, start + len(value)) if value else (a, b)

    def field(self, name):
        """(raw text, value, offsets of the value) like cut(), by whole words: the value runs from the first word that
        starts in the column to the end of the last; the raw text covers the column too. Cut once per line."""
        cut = self.fields.get(name)
        if cut is None:
            a, b = self.config.columns[name]
            words = self.words[name]
            if not words:
                cut = (self.line[a:b], "", (a, b))
            else:
                s, e = words[0][0], words[-1][1]
                cut = (self.line[min(a, s):max(b, e)], self.line[s:e], (s, e))
            self.fields[name] = cut
        return cut

    def blank(self, name, value_offsets):
        """True when the field is blank; an error when it may not be."""
        if not self.optional(name):
            self.error(f"MISSING_{name.upper()}", f"{name.replace('_', ' ').capitalize()} is blank; it is required.", name, "", *value_offsets)
        return True

    # the line -------------------------------------------------------------------------------------------------------
    def parse(self):
        cfg, cols = self.config, self.config.columns
        if self.base:
            self.warn("BYTE_ORDER_MARK", "A byte order mark starts the line; it is not part of any field.", None, BOM, 0, 1)
        if not self.text.strip():
            self.error("EMPTY_LINE", "The line is empty.", None, self.text, 0, len(self.text))
            return
        if self.text.lstrip().startswith(self.look.prefixes):
            self.record.message = _SPACE.sub(" ", self.text.strip())    # a system message, not an event: no fields
            return
        anomaly = cfg.anomaly_lines.get(self.text.strip())
        if anomaly:                                     # its own code alone; the text is never in the issue
            lead = len(self.text) - len(self.text.lstrip())
            self.error(anomaly, "The line is one of ANOMALY_LINES, an anomaly of its own; no field is read.",
                       None, None, lead, len(self.text.rstrip()))
            return
        gong = GONG_MARK.search(self.text) if "GONG" in self.text else None        # a substring test first: most lines
        if gong:
            self.gong_message(gong.start())
            return
        width = cfg.line_width
        if len(self.text) > width and self.text[width:].strip():
            tail = self.text[width:]
            lead = len(tail) - len(tail.lstrip())
            self.error("EXTRA_TRAILING_CONTENT", f"Text after position {width - 1}, the end of the line.", None, tail.strip(),
                       width + lead, width + lead + len(tail.strip()))
        elif len(self.text) < width:
            self.error("UNEXPECTED_LINE_WIDTH", f"The line is {len(self.text)} characters, not {width}.",
                       None, None, len(self.text), len(self.text))
        self.separators()
        self.assign_words()
        self.prefix(cols["prefix"])
        self.date(cols["date"])
        self.time(cols["time"])
        self.triplet(cols["numeric_triplet"])
        self.code(1)
        self.code(2)
        self.identifier(1)
        self.identifier(2)
        self.location()
        self.identifier_3_region()
        self.state_and_limit()
        self.timestamp()

    def separators(self, end=None):
        """Up to code 1 (prefix, date, time, triplet: cut at their positions), or up to end, every position between the
        columns must be blank; each run of text in one is reported once. Only the gap positions are looked at."""
        look, line = self.look, self.line
        end = look.body if end is None else end
        resume = 0                                      # the end of the run last reported
        for i in look.gap_list:
            if i >= end:
                break
            if i < resume or line[i].isspace():
                continue
            j = i
            while j < end and j in look.gaps and not line[j].isspace():
                j += 1
            before = next((name for (_, b), name in reversed(look.head) if b <= i), "the start")
            after = next((name for (a, _), name in look.head if a >= j), "code_1")
            self.error("MISSING_SEPARATOR", f"Position {i}{f'-{j - 1}' if j - 1 > i else ''} should be blank, between "
                       f"{before.replace('_', ' ')} and {after.replace('_', ' ')}.", None, line[i:j], i, j)
            resume = j

    def gong_message(self, start):
        """GONG APPEAR TONE after the date and time: a message with fields (GONG_MESSAGE). The prefix, date and time,
        and the triplet when it ends before the message, are read at their positions. Other text before the message,
        or a message not in its form, is an exception; an issue never holds the user's name. The message has no
        columns, so its width is not checked, as for the other messages."""
        cols, rec = self.config.columns, self.record
        body, time_end = cols["code_1"][0], cols["time"][1]
        if start < time_end:
            self.error("INVALID_GONG_LINE", "GONG APPEAR TONE must come after the date and time.", None, None, start, start)
            return
        with_triplet = cols["numeric_triplet"][1] <= start
        self.separators(min(start, body) if with_triplet else time_end)
        self.prefix(cols["prefix"])
        self.date(cols["date"])
        self.time(cols["time"])
        if with_triplet:
            self.triplet(cols["numeric_triplet"])
        before = body if with_triplet else time_end
        if self.line[before:start].strip():
            self.error("INVALID_GONG_LINE", "Text between the date and time (or the triplet) and GONG APPEAR TONE.",
                       None, None, before, start)
        found = GONG_MESSAGE.fullmatch(self.text, start)
        if found is None:
            self.error("INVALID_GONG_LINE", "Expected GONG APPEAR TONE ALMTYPE<0 to 7> O: <count> N: <count> <user name>, or "
                       "GONG APPEAR TONE SYSTEM <user name>; any whitespace between.", None, None, start, len(self.text.rstrip()))
        else:
            rec.alarm_type, rec.user_name = found[1] or found[4], found[5]
            if found[1]:
                rec.o_count, rec.n_count = int(found[2]), int(found[3])
            rec.message = _SPACE.sub(" ", self.text[start:found.start(5)].strip())     # the user's name is not in it
        self.timestamp()

    def assign_words(self):
        """From code 1 on, each word goes, whole, to the column it starts in, and may run on past it. Identifier 2 is one
        word: any more that start in its column begin the location early; and since nothing separates it from the
        location, a word running on past its column is cut there, as measured. A word that starts between two columns is
        an exception."""
        cols, width, look, line = self.config.columns, self.config.line_width, self.look, self.line
        body, owner_at, columns = look.body, look.owner, look.columns
        self.words = words = {name: [] for name in look.names}
        joined = body > 0 and not line[body - 1].isspace()        # a word from before code 1 running into it
        for match in _WORD.finditer(line, body):                 # the words from code 1 on; each column read off a table
            s, e = match.span()
            if s >= width or (s == body and joined):            # past the end: reported; from before code 1: cut there
                continue
            owner = owner_at[s]
            if owner is not None:
                words[owner].append((s, e))
                continue
            before = next(name for (_, b), name in reversed(columns) if b <= s)
            after = next((name for (a, _), name in columns if a > s), None)
            if after is None:
                self.error("EXTRA_TRAILING_CONTENT", f"Position {s}: text after the {before.replace('_', ' ')}, where the "
                           "line should be blank.", None, match.group(), s, e)
            else:
                self.error("WORD_BETWEEN_COLUMNS", f"A word starts at position {s}, between {before.replace('_', ' ')} and "
                           f"{after.replace('_', ' ')}, in neither column.", None, match.group(), s, e)
        second = self.words["identifier_2"]
        if second:
            (s, e), rest = second[0], second[1:]
            end = cols["identifier_2"][1]
            if e > end and end == cols["location"][0]:      # no gap to the location: a word filling the column is cut there
                second, rest = [(s, end)], [(end, e)]
            else:
                second = [(s, e)]
            self.words["identifier_2"], self.words["location"] = second, rest + self.words["location"]

    def prefix(self, span):
        """Each prefix character in its own position (PREFIXES: A at 0, G at 1, against the date): A, G, AG, or blank."""
        a, b = span
        raw = self.line[a:b]
        self.record.prefix_raw = raw
        marks = [i for i in range(a, b) if not self.line[i].isspace()]
        if marks and all(PREFIXES.get(self.line[i]) == i for i in marks):
            self.record.prefix = "".join(self.line[i] for i in marks)
        elif marks:
            where = ", ".join(f"{p} at {i}" for p, i in PREFIXES.items())
            self.error("INVALID_PREFIX", f"Each prefix character must be in its own position ({where}), or the prefix blank.",
                       "prefix", raw.strip(), marks[0], marks[-1] + 1)

    def date(self, span):
        raw, value, at = self.cut(span)
        if not value:
            self.blank("date", at)
            return
        checked = _check_date(raw, self.config.century)          # memoized: a month of logs has some thirty dates
        if checked[0] == "INVALID_DATE_FORMAT":
            self.error(checked[0], checked[1], "date", value, *at)
            return
        rec = self.record
        rec.date_raw = raw
        if checked[0]:
            self.error(checked[0], checked[1], "date", value, *at)
            return
        _, day, month, year, iso, leap_day = checked
        if leap_day:
            self.warn("LEAP_DAY_DEPENDS_ON_CENTURY", "29/02/00 exists in 2000 but not in 1900; no century was given.", "date", value, *at)
        rec.date_day, rec.date_month, rec.date_year_2digit = day, month, year
        if iso is not None:
            rec.date_iso = iso
            expected = self.config.expected_month
            if expected and rec.date_iso[:7] != expected:
                message = f"The line is dated {rec.date_iso[:7]}, but its folder is {expected}; a folder holds one month only."
                (self.error if self.config.strict_mode else self.warn)("DATE_OUTSIDE_FOLDER_MONTH", message, "date", value, *at)

    def time(self, span):
        raw, value, at = self.cut(span)
        if not value:
            self.blank("time", at)
            return
        checked = _check_time(raw)                                  # memoized: many lines to a second
        if checked is None:
            self.error("INVALID_TIME_FORMAT", "Expected the time as HH:mm:ss (24-hour).", "time", value, *at)
            return
        hour, minute, second = checked
        self.record.time_raw = raw
        if hour > 23 or minute > 59 or second > 59:
            self.error("INVALID_TIME_VALUE", "Hours run 00-23, minutes and seconds 00-59.", "time", value, *at)
        else:
            self.record.time_hour, self.record.time_minute, self.record.time_second = hour, minute, second

    def triplet(self, span):
        """Three right-aligned numbers and two slashes filling the column: " 1/51/21", "12/ 0/ 7"."""
        raw, value, at = self.cut(span)
        if not value:
            self.blank("numeric_triplet", at)
            return
        part = (len(raw) - 2) // 3
        parts = raw.split("/")
        if len(parts) != 3 or not all(len(p) == part and _TRIPLET_PART.fullmatch(p) for p in parts):
            self.error("INVALID_NUMERIC_TRIPLET", f"Expected three numbers, each right-aligned in {part} characters, between "
                       "two slashes (' 1/51/21').", "numeric_triplet", value, *at)
            return
        rec = self.record
        rec.numeric_triplet_raw = raw
        rec.triplet_first, rec.triplet_second, rec.triplet_third = (int(p) for p in parts)

    def code(self, n):
        name = f"code_{n}"
        _, value, at = self.field(name)
        if not value:
            self.blank(name, at)
        elif self.look.patterns[name].fullmatch(value):
            self.listed(name, f"Code {n}", value, *at)
        else:
            self.error(f"INVALID_CODE_{n}", f"Expected code {n} as two to six uppercase letters.", name, value, *at)

    def identifier(self, n):
        name = f"identifier_{n}"
        _, value, at = self.field(name)
        if not value:
            self.blank(name, at)
        elif not self.look.patterns["identifier"].fullmatch(value) and not (n == 2 and value in self.look.with_symbols):
            also = ", unless it is in IDENTIFIER_2_WITH_SYMBOLS" if n == 2 else ""
            self.error(f"INVALID_IDENTIFIER_{n}", f"Identifier {n} may only have letters, digits, _ and -{also}.", name, value, *at)
        else:
            self.listed(name, f"Identifier {n}", value, *at)

    def location(self):
        raw, value, at = self.field("location")
        rec = self.record
        rec.location_raw = raw
        if not value:
            self.blank("location", at)
            return
        rec.location = value
        rec.location_normalized = _SPACE.sub(" ", value)

    def identifier_3_region(self):
        """A reading (identifier 3, the unit, two numbers right-aligned to the ends of their columns) or identifier 3
        alone, from the words that start in identifier 3's column."""
        rc, words = self.config.reading_columns, self.words["identifier_3"]
        part = lambda name: [w for w in words if rc[name][0] <= w[0] < rc[name][1]]      # noqa: E731
        named, unit, n1, n2 = part("identifier_3"), part("unit_or_type"), part("number_1"), part("number_2")
        # by the layout alone: one word in the unit column and one number ending at the end of each number column
        reading = (len(unit) == len(n1) == len(n2) == 1 and len(named) + 3 == len(words)
                   and all(e < rc["identifier_3"][1] for _, e in named) and unit[0][1] <= rc["unit_or_type"][1]
                   and n1[0][1] == rc["number_1"][1] and n2[0][1] == rc["number_2"][1])
        if reading:
            self.record.is_reading = True
            self.identifier_3(named, rc["identifier_3"])
            (s, e), = unit
            self.unit(self.line[s:e], (s, e))
            self.number(rc["number_1"], 1)
            self.number(rc["number_2"], 2)
        else:
            self.identifier_3(words, self.config.columns["identifier_3"])

    def identifier_3(self, words, span):
        at = (words[0][0], words[-1][1]) if words else span
        value = self.line[at[0]:at[1]] if words else ""
        if not value:
            self.blank("identifier_3", at)
        elif not self.look.patterns["identifier_3"].fullmatch(value):
            self.error("INVALID_IDENTIFIER_3", "Identifier 3 may only have letters, digits, spaces between words, and - * ( ) _ / & .",
                       "identifier_3", value, *at)
        elif (value.islower() and value not in self.look.values["identifier_3"]
              and (self.look.keywords is None or self.look.keywords.search(value) is None)):
            self.record.user_name, self.name_at = value, at  # not listed and all lowercase: a user's name (see user_name)
        else:
            self.listed("identifier_3", "Identifier 3", value, *at, keywords=True)

    def unit(self, value, at):
        cfg, rec = self.config, self.record
        rec.unit_raw = value
        if value in self.look.no_unit:
            return                                      # a reading without a unit
        if value in self.look.units:
            rec.unit_or_type = value
        elif not _ALPHANUMERIC.fullmatch(value):
            self.error("INVALID_UNIT_OR_TYPE", f"{value!r} has a symbol but is not one of {_choices(cfg.allowed_units)}.",
                       "unit_or_type", value, *at)
        elif self.unknown("unit_or_type", "UNIT_OR_TYPE", "Unit/type", value, cfg.allowed_units, *at):
            rec.unit_or_type = value

    def number(self, span, n):
        name = f"number_{n}"
        raw, value, at = self.cut(span)
        setattr(self.record, f"{name}_raw", raw)
        if not value:
            self.blank(name, at)
            return
        if value in self.look.no_value:
            return                                          # written as having no value ("****.*"): no number, no error
        if not self.look.patterns["number"].fullmatch(value):
            self.error(f"INVALID_NUMBER_{n}", f"Number {n} must be digits, with a minus sign and a decimal point if any.", name, value, *at)
            return
        try:
            setattr(self.record, name, int(value) if _INTEGER.fullmatch(value) else Decimal(value))
        except (ValueError, InvalidOperation):
            self.error(f"INVALID_NUMBER_{n}", f"Number {n} fits the grammar but is not a number.", name, value, *at)

    def state(self):
        """One state; a space only in a listed one (NO SOURC, NOT SYNC)."""
        _, value, at = self.field("state")
        allowed = self.config.allowed_states
        if not value:
            self.blank("state", at)
        elif self.state_name(value) in self.look.states:
            self.record.state = self.state_name(value)
        elif " " in value:
            self.error("INVALID_STATE", f"Expected one state, one of {_choices(allowed)}.", "state", value, *at)
        elif self.unknown("state", "STATE", "State", value, allowed, *at):
            self.record.state = self.state_name(value)

    def state_name(self, value):
        """A state as stored: a spelling as the state it means (cPOWCON: POWCON), and always in upper case."""
        return self.config.state_spellings.get(value, value).upper()

    def state_and_limit(self):
        """The state and the limit code. A state written in the limit code column means the line has no limit code: it
        is the state when the state column is blank or holds the same state; a different state there is an exception.
        There a state is read as written (or as a spelling), since an all-lowercase word there is a user's name."""
        _, state, _ = self.field("state")
        _, limit, limit_at = self.field("limit_code")
        named = self.config.state_spellings.get(limit, limit)
        if named not in self.look.states:
            self.state()
            self.limit_code()
        elif not state or self.state_name(state) == named:
            self.record.state = named
        else:
            self.state()
            self.warn("TWO_STATES", "The state column and the limit code column hold different states; the state column's "
                      "is kept.", "limit_code", limit, *limit_at)

    def user_name(self, value):
        """An all-lowercase word in the limit code column: a user's name. When identifier 3 held a different one, the limit
        code's is the user's name, and identifier 3's is identifier 3 after all (unclassified until listed)."""
        held, self.record.user_name = self.record.user_name, value
        if held is not None and held != value:
            self.listed("identifier_3", "Identifier 3", held, *self.name_at, keywords=True)

    def limit_code(self):
        """An allowed limit code, then any text after it (limit_suffix), to the end of the line. An all-lowercase word
        instead of a limit code is a user's name."""
        _, value, at = self.field("limit_code")
        allowed = self.config.allowed_limit_codes
        if not value:
            self.blank("limit_code", at)
            return
        code = next((c for c in self.look.limit_codes if value.startswith(c)), None)     # longest first, sorted once
        if code is not None:
            self.record.limit_code = code
            self.record.limit_suffix = value[len(code):].strip() or None
        elif value.islower():
            self.user_name(value)                           # no limit code: a user's name
        elif self.unknown("limit_code", "LIMIT_CODE", "Limit code", value, allowed, *at):
            self.record.limit_code = value                  # lenient: kept whole, since where its code ends is not known

    def timestamp(self):
        """The date and time as one moment, in the log's own offset and in UTC (only when both are valid)."""
        rec = self.record
        if rec.date_iso is None or rec.time_hour is None:
            return
        rec.timestamp, rec.timestamp_utc = _moment(rec.date_iso, rec.time_hour, rec.time_minute, rec.time_second,
                                                   self.config.utc_offset)


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


# Memoized checks: pure functions of a column's text, which repeats from line to line (a month of logs has some
# thirty dates, and many lines share a second), so each distinct value is worked out once. The caches are small (4,096
# values): the lines come in time order, so the recent values are the ones that repeat, and a worker stays small.

@lru_cache(maxsize=4096)
def _check_date(raw: str, century: int | None) -> tuple:
    """A date column's text: (error code, message), or (None, day, month, year, the ISO date or None without a century,
    whether it is 29/02/00 without a century)."""
    if not _DATE.fullmatch(raw):
        return ("INVALID_DATE_FORMAT", "Expected the date as DD/MM/YY.")
    day, month, year = (int(x) for x in raw.split("/"))
    if not 1 <= month <= 12:
        return ("INVALID_CALENDAR_DATE", f"Month {month:02d} does not exist.")
    leap = _is_leap(century + year) if century is not None else year % 4 == 0
    if not 1 <= day <= (29 if month == 2 and leap else _DAYS[month - 1]):
        return ("INVALID_CALENDAR_DATE", f"Day {day:02d} does not exist in month {month:02d}.")
    iso = f"{century + year:04d}-{month:02d}-{day:02d}" if century is not None else None
    return (None, day, month, year, iso, century is None and (day, month, year) == (29, 2, 0))


@lru_cache(maxsize=4096)
def _check_time(raw: str) -> tuple[int, int, int] | None:
    """A time column's text: (hour, minute, second) when it is HH:mm:ss, else None (the values are checked after)."""
    if not _TIME.fullmatch(raw):
        return None
    hour, minute, second = (int(x) for x in raw.split(":"))
    return hour, minute, second


@lru_cache(maxsize=16)
def _tz(utc_offset: str) -> timezone:
    sign, hours, minutes = _OFFSET.fullmatch(utc_offset).groups()
    delta = timedelta(hours=int(hours), minutes=int(minutes))
    return timezone(delta if sign == "+" else -delta)


@lru_cache(maxsize=4096)
def _moment(date_iso: str, hour: int, minute: int, second: int, utc_offset: str) -> tuple[str, str]:
    """The moment in the log's offset and in UTC, as ISO 8601 text."""
    year, month, day = (int(x) for x in date_iso.split("-"))
    moment = datetime(year, month, day, hour, minute, second, tzinfo=_tz(utc_offset))
    return moment.isoformat(), moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
