"""Tests for the event log parser (event_log_parser.py) and its Phase 1 run over the .gz folders (event_log.py).
Every line here is made up; none comes from the logs.

    .venv/Scripts/python.exe -m unittest discover -s pipeline/phase1_classify -p "test_event_log.py" -v
"""
from __future__ import annotations

import contextlib
import csv
import dataclasses
import gzip
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import event_log  # noqa: E402
import event_log_devices  # noqa: E402
from event_log_devices import STATE_GROUPS, check_groups, classify, other_states  # noqa: E402
from event_log_parser import (CLASSIFICATION_FIELDS, COLUMNS, INVALID, LIMIT_CODES, LINE_WIDTH, MESSAGE, PARSED,  # noqa: E402
                              PARSED_WITH_WARNINGS, READING_COLUMNS, STATES, UNCLASSIFIED, UNITS, ParserConfig, parse_line)

# Tests never depend on the lists filled in event_log_parser.py: every config sets all five, the keywords and the
# anomaly lines, and classification is off unless a test is about it.
NEUTRAL = dict(code_1_values=(), code_2_values=(), identifier_1_values=(), identifier_2_values=(), identifier_3_values=(),
               identifier_2_with_symbols=(), identifier_3_keywords=(), identifier_3_states=(), anomaly_lines={},
               classification_fields=())


def config(**changes) -> ParserConfig:
    return ParserConfig(**{**NEUTRAL, **changes})


CONFIG = config()
STRICT = config(strict_mode=True)


def make(prefix="A", date="19/10/26", time="14:35:02", triplet=" 1/51/21", code_1="ABC", code_2="DEF", id1="ID001", id2="ID002",
         location="Main Plant Room", id3="ID003", unit="DEGC", n1="12.5", n2="34.0", state="RUN", limit="U1",
         reading=True, eol="", over=()) -> str:
    """A line in the measured layout. reading=False puts id3 alone in the identifier 3 column (unit and numbers unused).
    over: (position, text) pairs written over the line afterwards, for text that breaks the columns."""
    line = [" "] * LINE_WIDTH

    def put(span, text, right=False):
        a, b = span
        text = text.rjust(b - a) if right else text.ljust(b - a)
        assert len(text) == b - a, (span, text)
        line[a:b] = text

    put(COLUMNS["prefix"], prefix or " ")
    for name, value in (("date", date), ("time", time), ("numeric_triplet", triplet), ("code_1", code_1), ("code_2", code_2),
                        ("identifier_1", id1), ("identifier_2", id2), ("location", location), ("state", state),
                        ("limit_code", limit)):
        put(COLUMNS[name], value)
    if reading:
        put(READING_COLUMNS["identifier_3"], id3)
        put(READING_COLUMNS["unit_or_type"], unit)
        put(READING_COLUMNS["number_1"], n1, right=True)
        put(READING_COLUMNS["number_2"], n2, right=True)
    else:
        put(COLUMNS["identifier_3"], id3)
    for position, text in over:
        line[position:position + len(text)] = text
    return "".join(line) + eol


def parse(line, settings=CONFIG):
    return parse_line(line, 1, "test", settings)


def codes(record) -> list[str]:
    return [i.code for i in record.errors + record.warnings]


class ValidRecords(unittest.TestCase):
    def ok(self, line, settings=CONFIG):
        record = parse(line, settings)
        self.assertEqual(record.parse_status, PARSED, codes(record))
        return record

    def test_a_reading(self):
        r = self.ok(make())
        self.assertEqual(len(make()), 132)
        self.assertEqual((r.prefix, r.date_iso, r.time_raw, r.numeric_triplet_raw), ("A", "2026-10-19", "14:35:02", " 1/51/21"))
        self.assertEqual((r.triplet_first, r.triplet_second, r.triplet_third), (1, 51, 21))
        self.assertEqual((r.code_1, r.code_2, r.identifier_1, r.identifier_2), ("ABC", "DEF", "ID001", "ID002"))
        self.assertEqual((r.location, r.identifier_3, r.is_reading, r.unit_or_type), ("Main Plant Room", "ID003", True, "DEGC"))
        self.assertEqual((r.number_1, r.number_2, r.state, r.limit_code), (Decimal("12.5"), Decimal("34.0"), "RUN", "U1"))
        self.assertEqual(r.raw_line, make())

    def test_a_status_line(self):
        r = self.ok(make(id3="Pump House Fan Status 2", reading=False, state="OFF", limit=""))
        self.assertEqual((r.identifier_3, r.is_reading, r.unit_or_type, r.number_1, r.number_2), ("Pump House Fan Status 2", False, None, None, None))

    def test_timestamps_are_utc_plus_8(self):
        r = self.ok(make())
        self.assertEqual((r.timestamp, r.timestamp_utc), ("2026-10-19T14:35:02+08:00", "2026-10-19T06:35:02Z"))
        self.assertEqual(self.ok(make(time="03:00:00")).timestamp_utc, "2026-10-18T19:00:00Z")

    def test_prefix_a_g_and_blank(self):
        self.assertEqual(self.ok(make(prefix="A")).prefix, "A")
        g = self.ok(make(prefix=" G"))                                                          # G against the date
        self.assertEqual((g.prefix, g.prefix_raw, g.date_raw), ("G", " G", "19/10/26"))
        both = self.ok(make(prefix="AG"))                                                        # A, then G against the date
        self.assertEqual((both.prefix, both.prefix_raw), ("AG", "AG"))
        blank = self.ok(make(prefix=None))
        self.assertEqual((blank.prefix, blank.prefix_raw), (None, "  "))

    def test_triplet_forms(self):
        for triplet, numbers in ((" 1/51/21", (1, 51, 21)), (" 1/ 9/ 3", (1, 9, 3)), ("12/ 0/ 7", (12, 0, 7)), ("12/34/56", (12, 34, 56))):
            r = self.ok(make(triplet=triplet))
            self.assertEqual((r.triplet_first, r.triplet_second, r.triplet_third), numbers)

    def test_every_unit_state_and_limit_code(self):
        for unit in UNITS:
            self.assertEqual(self.ok(make(unit=unit)).unit_or_type, unit)
        for state in STATES:
            self.assertEqual(self.ok(make(state=state)).state, state)
        for limit in LIMIT_CODES:
            self.assertEqual(self.ok(make(limit=limit)).limit_code, limit)

    def test_a_limit_code_with_an_asterisk(self):
        r = self.ok(make(limit="W*ACK"))                                                        # W*, written as such
        self.assertEqual((r.limit_code, r.limit_suffix), ("W*", "ACK"))
        self.assertEqual(self.ok(make(limit="WE")).limit_code, "WE")

    def test_the_limit_code_may_carry_any_text_after_it(self):
        spaced = self.ok(make(limit="U1 ackd by op 2"))
        self.assertEqual((spaced.limit_code, spaced.limit_suffix), ("U1", "ackd by op 2"))
        joined = self.ok(make(limit="WEx9"))
        self.assertEqual((joined.limit_code, joined.limit_suffix), ("WE", "x9"))
        self.assertEqual(self.ok(make(limit="MU")).limit_suffix, None)
        self.assertEqual(self.ok(make(over=((119, "ackd"),))).limit_suffix, "ackd")               # the old 119-126 words

    def test_a_dash_unit_means_no_unit(self):
        r = self.ok(make(unit="-"))
        self.assertEqual((r.is_reading, r.unit_raw, r.unit_or_type, r.number_1), (True, "-", None, Decimal("12.5")))

    def test_numbers_whole_or_decimal_kept_exact(self):
        r = self.ok(make(n1="230", n2="12.50"))
        self.assertEqual((r.number_1, r.number_2), (230, Decimal("12.50")))
        self.assertIsInstance(r.number_1, int)
        self.assertEqual(r.to_row()["number_2"], "12.50")
        negative = self.ok(make(n1="-483.5", n2="-3"))                                        # a minus sign
        self.assertEqual((negative.number_1, negative.number_2), (Decimal("-483.5"), -3))
        self.assertIsInstance(negative.number_2, int)

    def test_optional_fields_may_be_blank(self):
        r = self.ok(make(triplet="", code_1="", code_2="", id1="", id2="", location="", id3="", state="", limit=""))
        self.assertEqual((r.numeric_triplet_raw, r.code_1, r.code_2, r.identifier_1, r.identifier_2, r.location, r.identifier_3,
                          r.state, r.limit_code), (None,) * 9)

    def test_identifier_2_may_fill_its_column_and_touch_the_location(self):
        r = self.ok(make(id2="ABCDEFGH9", location="Room 1"))
        self.assertEqual((r.identifier_2, r.location), ("ABCDEFGH9", "Room 1"))

    def test_identifier_2_running_on_into_the_location_starts_the_location_early(self):
        r = self.ok(make(id2="ABC", location="", over=((50, "DEF-GHI JK"),)))                 # "ABC DEF-G|HI JK"
        self.assertEqual((r.identifier_2, r.location, r.location_raw), ("ABC", "DEF-GHI JK", "DEF-GHI JK".ljust(25)))

    def test_any_space_inside_identifier_2s_column_starts_the_location_early(self):
        for id2, location, expected in (("ABC XYZ", "", "XYZ"),                                  # inside the column, location blank
                                        ("AB012 XYZ", " QRS", "XYZ QRS"),                        # a space on the boundary
                                        ("AB CD", "Main Plant Room", "CD    Main Plant Room")):  # words in both columns
            r = self.ok(make(id2=id2, location=location))
            self.assertEqual((r.identifier_2, r.location), (id2.split()[0], expected), id2)
        self.assertEqual(r.location_normalized, "CD Main Plant Room")

    def test_codes_of_two_to_six_letters(self):
        r = self.ok(make(code_1="AB", code_2="CD"))
        self.assertEqual((r.code_1, r.code_2), ("AB", "CD"))
        four = self.ok(make(code_2="", over=((29, "ABCD"),)))
        self.assertEqual((four.code_1, four.code_2), ("ABCD", None))
        r = self.ok(make(code_2="", id1="", over=((29, "ABCDE FGHIJ  XY1"),)))
        self.assertEqual((r.code_1, r.code_2, r.identifier_1), ("ABCDE", "FGHIJ", "XY1"))
        six = self.ok(make(code_2="", over=((29, "ABCDEF"),)))                               # across code 2's column
        self.assertEqual((six.code_1, six.code_2), ("ABCDEF", None))
        six = self.ok(make(code_2="", id1="", over=((33, "ABCDEF  XY1"),)))                  # into identifier 1's column
        self.assertEqual((six.code_2, six.identifier_1), ("ABCDEF", "XY1"))

    def test_a_word_is_never_split_and_may_run_past_its_column(self):
        r = self.ok(make(id1="", id2="", over=((39, "ABCDEFGH  XY2"),)))                    # identifier 1 runs past 44
        self.assertEqual((r.identifier_1, r.identifier_2), ("ABCDEFGH", "XY2"))
        long = self.ok(make(id3="", reading=False, state="", over=((76, "A" * 31 + "  RUN"),)))  # into the state's column
        self.assertEqual((long.identifier_3, long.state), ("A" * 31, "RUN"))

    def test_a_command_failure_line_is_a_system_message(self):
        r = parse(("  Command Failure :" + " " * 28 + "Link lost !").ljust(LINE_WIDTH))
        self.assertEqual((r.parse_status, r.message, r.errors, r.warnings, r.date_raw, r.state),
                         (MESSAGE, "Command Failure : Link lost !", [], [], None, None))
        self.assertEqual(parse("Command Failure : anything else").message, "Command Failure : anything else")
        self.assertEqual(parse("  Command failure : Link lost !".ljust(LINE_WIDTH)).parse_status, INVALID)   # exact text

    def test_an_identifier_3_that_is_a_state_moves_to_the_state(self):
        moving = config(identifier_3_states=("MV_U", "MV-PF"))
        r = self.ok(make(id3="MV_U", unit="V", n1="22.1", state="APP"), moving)              # a reading: its state replaced
        self.assertEqual((r.identifier_3, r.state, r.is_reading, r.unit_or_type, r.number_1), (None, "MV_U", True, "V", Decimal("22.1")))
        r = self.ok(make(id3="MV-PF", reading=False, state="", limit=""), moving)            # no state before
        self.assertEqual((r.identifier_3, r.state), (None, "MV-PF"))
        self.assertEqual(self.ok(make(id3="MV_I", reading=False), moving).identifier_3, "MV_I")   # exact
        self.assertEqual(self.ok(make(id3="MV_U", reading=False)).identifier_3, "MV_U")         # only when listed
        listed = config(identifier_3_values=("MV_U",), identifier_3_states=("MV_U",), classification_fields=("identifier_3",))
        self.assertEqual(self.ok(make(id3="MV_U", reading=False), listed).state, "MV_U")        # classified first, then moved

    def test_a_gong_line_is_a_message_with_fields(self):
        head = "A 19/10/26 14:35:02  1/51/21 "
        for line in (head + "GONG  APPEAR   TONE     ALMTYPE3      O:     12      N: 13        operator1",
                     (head + "GONG APPEAR TONE ALMTYPE3 O: 12 N: 13 operator1").ljust(LINE_WIDTH),
                     "A 19/10/26 14:35:02 GONG APPEAR TONE ALMTYPE3 O: 12 N: 13 operator1"):              # no triplet
            r = parse(line)
            self.assertEqual((r.parse_status, r.errors, r.warnings), (MESSAGE, [], []), line)
            self.assertEqual((r.message, r.alarm_type, r.o_count, r.n_count, r.user_name, r.timestamp),
                             ("GONG APPEAR TONE ALMTYPE3 O: 12 N: 13", "ALMTYPE3", 12, 13, "operator1",
                              "2026-10-19T14:35:02+08:00"), line)
        self.assertEqual(parse(head + "GONG APPEAR TONE ALMTYPE3 O:7 N:8 op2").o_count, 7)
        for n in range(0, 8):                                                                   # ALMTYPE0 to ALMTYPE7
            r = parse(head + f"GONG APPEAR TONE ALMTYPE{n} O: 1 N: 2 op2")
            self.assertEqual((r.parse_status, r.alarm_type, r.o_count, r.n_count), (MESSAGE, f"ALMTYPE{n}", 1, 2), n)
        system = parse("  21/10/26 10:00:00          GONG    APPEAR   TONE       SYSTEM" + " " * 56 + "operator1")   # as given
        self.assertEqual((system.parse_status, system.errors, system.prefix, system.numeric_triplet_raw, system.timestamp),
                         (MESSAGE, [], None, None, "2026-10-21T10:00:00+08:00"))
        self.assertEqual((system.message, system.alarm_type, system.o_count, system.n_count, system.user_name),
                         ("GONG APPEAR TONE SYSTEM", "SYSTEM", None, None, "operator1"))
        self.assertEqual(parse(head + "GONG APPEAR TONE ALMTYPE3 O: 7 N: 8 op2").triplet_first, 1)

    def test_a_reading_with_no_value(self):
        r = self.ok(make(n1="****.*", n2="****.*"))
        self.assertEqual((r.is_reading, r.number_1_raw, r.number_1, r.number_2_raw, r.number_2), (True, " ****.*", None, " ****.*", None))

    def test_a_state_in_the_limit_code_column_means_no_limit_code(self):
        for state in ("", "OFF"):                                                            # the state column blank or the same
            r = self.ok(make(state=state, limit="OFF"))
            self.assertEqual((r.state, r.limit_code), ("OFF", None), state)

    def test_a_state_is_stored_in_upper_case(self):
        for written in ("Online", "online", "ONLINE"):
            self.assertEqual(self.ok(make(state=written, limit="")).state, "ONLINE", written)
        self.assertEqual(self.ok(make(state="Online", limit="ONLINE")).state, "ONLINE")         # the same state in both columns
        r = self.ok(make(state="ONLINE", limit="online"))                                       # all lowercase there: a user's name
        self.assertEqual((r.state, r.limit_code, r.user_name), ("ONLINE", None, "online"))

    def test_a_spelling_with_a_lowercase_c_is_read_without_it(self):
        for state, limit in (("cPOWCON", ""), ("", "cPOWCON"), ("POWCON", "cPOWCON"), ("cPOWCON", "POWCON")):
            r = self.ok(make(state=state, limit=limit))
            self.assertEqual((r.state, r.limit_code), ("POWCON", None), (state, limit))
        self.assertEqual(self.ok(make(state="cSCBKWH", limit="")).state, "SCBKWH")

    def test_a_listed_state_may_have_a_space(self):
        for state in ("NO SOURC", "NOT SYNC", "No Sourc"):
            self.assertEqual(self.ok(make(state=state, limit="")).state, state.upper(), state)
        self.assertEqual(self.ok(make(state="", limit="NOT SYNC")).state, "NOT SYNC")            # in the limit code column too

    def test_a_lowercase_word_for_the_limit_code_is_a_user_name(self):
        r = self.ok(make(limit="operator2"))
        self.assertEqual((r.user_name, r.limit_code, r.limit_suffix), ("operator2", None, None))
        self.assertEqual(self.ok(make(limit="u1")).user_name, "u1")                           # all lowercase: not a limit code
        self.assertEqual(self.ok(make(id3="operator2", reading=False, limit="operator2")).user_name, "operator2")
        two = self.ok(make(id3="device locked", reading=False, limit="operator2"))             # different: the limit code's
        self.assertEqual((two.user_name, two.identifier_3), ("operator2", "device locked"))

    def test_the_symbols_seen_are_allowed(self):
        r = self.ok(make(id1="AB_CD", id2="AB-12_3", id3="FAN (A)/B & C.D*", reading=False))
        self.assertEqual((r.identifier_1, r.identifier_2, r.identifier_3), ("AB_CD", "AB-12_3", "FAN (A)/B & C.D*"))
        self.assertEqual(self.ok(make(location="Rm.2/3 (A&B),O'Nl!")).location, "Rm.2/3 (A&B),O'Nl!")

    def test_line_endings(self):
        for eol in ("\n", "\r\n"):
            self.assertEqual(self.ok(make(eol=eol)).raw_line, make())
        self.ok(make() + "    ")                                                             # trailing spaces past the end

    def test_values_may_sit_anywhere_in_their_column(self):
        right = parse(make(id1="   ID001", id2="    ID002", location="     Main Plant Room"))
        self.assertEqual((right.identifier_1, right.identifier_2, right.location), ("ID001", "ID002", "Main Plant Room"))


class InvalidRecords(unittest.TestCase):
    def bad(self, line, code, settings=CONFIG):
        record = parse(line, settings)
        self.assertEqual(record.parse_status, INVALID, codes(record))
        self.assertIn(code, [e.code for e in record.errors])
        return record

    def warned(self, line, code, settings=CONFIG):
        record = parse(line, settings)
        self.assertEqual(record.parse_status, PARSED_WITH_WARNINGS, codes(record))
        self.assertIn(code, [w.code for w in record.warnings])
        return record

    def test_dates_and_times(self):
        self.bad(make(date="31/02/26"), "INVALID_CALENDAR_DATE")
        self.bad(make(date="29/02/25"), "INVALID_CALENDAR_DATE")
        self.assertEqual(parse(make(date="29/02/24")).parse_status, PARSED)
        self.bad(make(date="1/2/2026"), "INVALID_DATE_FORMAT")
        self.bad(make(date=""), "MISSING_DATE")
        self.bad(make(time="25:70:00"), "INVALID_TIME_VALUE")
        self.bad(make(time="2:35:2PM"), "INVALID_TIME_FORMAT")

    def test_triplets(self):
        for triplet in ("1/51/21", "1 / 9/ 3", "123/1/11", " 1-51-21", "1/51/21 "):
            self.bad(make(triplet=triplet), "INVALID_NUMERIC_TRIPLET")

    def test_codes(self):
        for code in ("abc", "A", "Ab", "A1C", "A_C"):
            self.bad(make(code_1=code), "INVALID_CODE_1")
            self.bad(make(code_2=code), "INVALID_CODE_2")
        self.bad(make(over=((29, "ABCDEFG"),)), "INVALID_CODE_1")                            # seven, across both columns
        self.bad(make(code_2="", id1="", over=((33, "ABCDEFG  XY1"),)), "INVALID_CODE_2")    # seven

    def test_identifiers(self):
        self.bad(make(id1="AB#1"), "INVALID_IDENTIFIER_1")
        self.bad(make(id3="FAN#1", reading=False), "INVALID_IDENTIFIER_3")

    def test_a_symbol_in_identifier_2_is_an_exception(self):
        self.bad(make(id2="AB#1"), "INVALID_IDENTIFIER_2")
        self.bad(make(id2="A#B CD"), "INVALID_IDENTIFIER_2")                                 # its first word, once split

    def test_an_identifier_2_with_a_symbol_only_when_listed(self):
        known = config(identifier_2_with_symbols=("AB&1",))
        self.assertEqual(parse(make(id2="AB&1"), known).identifier_2, "AB&1")
        self.assertEqual(parse(make(id2="AB&1"), known).parse_status, PARSED)
        self.bad(make(id2="AB&2"), "INVALID_IDENTIFIER_2", known)                            # exact
        self.bad(make(id1="AB&1"), "INVALID_IDENTIFIER_1", known)                            # identifier 2 only

    def test_units(self):
        self.assertEqual(parse(make(unit="L/S")).unit_or_type, "L/S")                         # a listed unit, symbol and all
        self.bad(make(unit="m/s"), "INVALID_UNIT_OR_TYPE")                                   # a symbol: an error, lenient or not
        kpa = self.warned(make(unit="KPA"), "UNKNOWN_UNIT_OR_TYPE")
        self.assertEqual(kpa.unit_or_type, "KPA")
        self.bad(make(unit="KPA"), "INVALID_UNIT_OR_TYPE", STRICT)

    def test_numbers(self):
        for value in ("+3", "--3", "3-", "-", "1,5", "1.2.3", "***.**"):
            self.bad(make(n1=value), "INVALID_NUMBER_1")
            self.bad(make(n2=value), "INVALID_NUMBER_2")

    def test_a_word_starting_between_two_columns_is_an_exception(self):
        self.bad(make(id2="", over=((45, "XY2"),)), "WORD_BETWEEN_COLUMNS")

    def test_a_reading_needs_its_whole_layout(self):
        # a word in the unit column and a word ending where number 1 ends, but nothing where number 2 ends: identifier 3
        r = parse(make(id3="Fan Room Main Status", reading=False))
        self.assertEqual((r.parse_status, r.is_reading, r.identifier_3), (PARSED, False, "Fan Room Main Status"))
        # the whole layout with letters where a number belongs: a reading, and an exception
        self.bad(make(n1="Status"), "INVALID_NUMBER_1")

    def test_states_and_limit_codes(self):
        for state in ("RUNNING", "ACK", "running"):
            self.assertEqual(self.warned(make(state=state), "UNKNOWN_STATE").state, state.upper())   # kept, in upper case
            self.bad(make(state=state), "INVALID_STATE", STRICT)
        self.bad(make(state="ON OFF"), "INVALID_STATE")
        self.assertEqual(self.warned(make(limit="HH"), "UNKNOWN_LIMIT_CODE").limit_code, "HH")
        self.assertEqual(self.warned(make(limit="", over=((119, "Ackd"),)), "UNKNOWN_LIMIT_CODE").limit_code, "Ackd")
        self.bad(make(limit="HH"), "INVALID_LIMIT_CODE", STRICT)
        two = self.warned(make(state="ON", limit="OFF"), "TWO_STATES")                        # a different state in each
        self.assertEqual((two.state, two.limit_code), ("ON", None))

    def test_separators_and_the_end_of_the_line(self):
        self.bad(make(over=((10, "X"),)), "MISSING_SEPARATOR")
        self.bad(make() + "extra", "EXTRA_TRAILING_CONTENT")                                # past the end of the line
        self.bad(make().rstrip(), "UNEXPECTED_LINE_WIDTH")                                  # every line is 132 characters
        self.bad("", "EMPTY_LINE")

    def test_a_gong_line_not_in_its_form_is_an_exception(self):
        head = "A 19/10/26 14:35:02  1/51/21 "
        for line in (head + "GONG APPEAR TONE ALMTYPE8 O: 12 N: 13 operator1",                    # another alarm type
                     head + "GONG APPEAR TONE ALMTYPE10 O: 12 N: 13 operator1",
                     head + "GONG APPEAR TONE ALMTYPE O: 12 N: 13 operator1",
                     head + "GONG APPEAR TONE ALMTYPE3 O: 12 N: 13",                                # no user name
                     head + "GONG APPEAR TONE ALMTYPE3 operator1",                                  # an ALMTYPE without counts
                     head + "GONG APPEAR TONE SYSTEM O: 12 N: 13 operator1",                        # SYSTEM with counts
                     head + "GONG APPEAR TONE SYSTEM",                                              # no user name
                     head + "GONG APPEAR TONE ALMTYPE3 O: 12 N: 13 operator1 more",                 # more after it
                     head + "POW GONG APPEAR TONE ALMTYPE3 O: 12 N: 13 operator1",                  # text before it
                     "GONG APPEAR TONE ALMTYPE3 O: 12 N: 13 operator1"):                            # no date and time
            r = self.bad(line, "INVALID_GONG_LINE")
            self.assertTrue(all(e.value is None for e in r.errors), line)                          # never the user's name
        self.bad("A 31/02/26 14:35:02  1/51/21 GONG APPEAR TONE ALMTYPE3 O: 1 N: 2 operator1", "INVALID_CALENDAR_DATE")

    def test_prefix(self):
        for prefix in ("B", "G", " A", "GA", "AB"):                                            # each in its own position
            self.bad(make(prefix=prefix), "INVALID_PREFIX")

    def test_an_anomaly_line_has_its_own_code_alone(self):
        known = config(anomaly_lines={"Made up line 7": "MADE_UP_LINE"})
        for line in ("Made up line 7", "  Made up line 7".ljust(LINE_WIDTH)):                     # whatever its width
            r = self.bad(line, "MADE_UP_LINE", known)
            self.assertEqual((codes(r), r.errors[0].value, r.date_raw, r.prefix_raw), (["MADE_UP_LINE"], None, None, None))
        self.assertEqual(parse("  Made up line 7", known).errors[0].start_offset, 2)
        for other in ("Made up line 8", "made up line 7", "Made up  line 7", "Made up line 7 and more"):  # the exact text only
            self.assertNotIn("MADE_UP_LINE", codes(parse(other, known)), other)

    def test_a_folder_holds_one_month(self):
        october = config(expected_month="2026-10")
        self.assertEqual(parse(make(), october).parse_status, PARSED)
        self.warned(make(date="01/11/26"), "DATE_OUTSIDE_FOLDER_MONTH", october)
        self.bad(make(date="30/09/26"), "DATE_OUTSIDE_FOLDER_MONTH", dataclasses.replace(october, strict_mode=True))

    def test_errors_point_at_the_characters(self):
        r = parse(make(state="ON OFF", unit="m/s", date="31/02/26", n1="+3", id1="AB#1"), STRICT)
        self.assertEqual(len(r.errors), 5)
        for issue in r.errors:
            self.assertEqual(r.raw_line[issue.start_offset:issue.end_offset], issue.value, issue.code)
        bom = parse("﻿" + make(state="ON OFF"))
        issue = next(e for e in bom.errors if e.code == "INVALID_STATE")
        self.assertEqual(bom.raw_line[issue.start_offset:issue.end_offset], "ON OFF")
        self.assertIn("BYTE_ORDER_MARK", codes(bom))


class Classification(unittest.TestCase):
    """A line is classified once its code 1, identifier 1 and identifier 3 are in their lists; until then it is
    'unclassified' (kept, not an error), in lenient and strict mode alike."""

    LISTS = config(code_1_values=("ABC", "PLC"), identifier_1_values=("ID001", "TAG10"), identifier_3_values=("ID003", "FAN 4"),
                   classification_fields=CLASSIFICATION_FIELDS)

    def test_listed_values_classify_the_line(self):
        r = parse(make(), self.LISTS)
        self.assertEqual((r.parse_status, r.unclassified_fields), (PARSED, []))
        other = parse(make(id1="TAG10", id2="ANYTHING9", code_2="ZZZ"), self.LISTS)        # code 2 and identifier 2 are not listed
        self.assertEqual(other.parse_status, PARSED)

    def test_each_unlisted_field_leaves_the_line_unclassified(self):
        code = parse(make(code_1="XYZ"), self.LISTS)
        self.assertEqual((code.parse_status, code.unclassified_fields, code.code_1, codes(code)),
                         (UNCLASSIFIED, ["code_1"], "XYZ", ["UNCLASSIFIED_CODE_1"]))
        first = parse(make(id1="ZZ9"), self.LISTS)
        self.assertEqual((first.unclassified_fields, first.identifier_1), (["identifier_1"], "ZZ9"))
        third = parse(make(id3="PUMP 9", reading=False), self.LISTS)
        self.assertEqual((third.unclassified_fields, third.identifier_3), (["identifier_3"], "PUMP 9"))
        every = parse(make(code_1="XYZ", id1="ZZ9", id3="PUMP 9", reading=False), self.LISTS)
        self.assertEqual(every.unclassified_fields, ["code_1", "identifier_1", "identifier_3"])

    def test_matching_is_exact_like_a_password(self):
        for near in ("FAN  4", "Fan 4"):
            r = parse(make(id3=near, reading=False), self.LISTS)
            self.assertEqual(r.unclassified_fields, ["identifier_3"], near)
        self.assertEqual(parse(make(id3="fan 4", reading=False), self.LISTS).user_name, "fan 4")     # all lowercase: a user's name

    def test_a_keyword_classifies_identifier_3(self):
        words = dataclasses.replace(self.LISTS, identifier_3_keywords=("Contactor Energise", "Live"))
        for value in ("E12Contactor Energise", "Contactor Energise", "E27_E28 Live", "T99 Live", "3rd Rail Live 9"):
            r = parse(make(id3=value, reading=False), words)
            self.assertEqual((r.parse_status, r.identifier_3, r.unclassified_fields), (PARSED, value, []), value)
        for value in ("E12Contactor energise", "T99 LIVE", "Contactor"):                     # exact case, the whole keyword
            r = parse(make(id3=value, reading=False), words)
            self.assertEqual(r.unclassified_fields, ["identifier_3"], value)

    def test_an_unlisted_lowercase_identifier_3_is_a_user_name(self):
        r = parse(make(id3="operator1", reading=False), self.LISTS)
        self.assertEqual((r.parse_status, r.user_name, r.identifier_3, r.unclassified_fields, codes(r)),
                         (PARSED, "operator1", None, [], []))
        self.assertEqual(r.to_row()["user_name"], "operator1")
        two = parse(make(id3="device locked", reading=False, limit="operator1"), self.LISTS)  # the limit code's is the name
        self.assertEqual((two.parse_status, two.user_name, two.identifier_3, two.unclassified_fields),
                         (UNCLASSIFIED, "operator1", "device locked", ["identifier_3"]))
        listed = parse(make(id3="spare", reading=False), dataclasses.replace(self.LISTS, identifier_3_values=("spare",)))
        self.assertEqual((listed.identifier_3, listed.user_name), ("spare", None))                  # a listed value stays identifier 3
        for other in ("Operator1", "OPERATOR1", "12 34"):                                         # not all lowercase
            r = parse(make(id3=other, reading=False), self.LISTS)
            self.assertEqual((r.user_name, r.unclassified_fields), (None, ["identifier_3"]), other)

    def test_unclassified_is_not_an_error_even_when_strict(self):
        r = parse(make(code_1="XYZ"), dataclasses.replace(self.LISTS, strict_mode=True))
        self.assertEqual((r.parse_status, r.errors), (UNCLASSIFIED, []))

    def test_empty_lists_leave_every_line_unclassified(self):
        r = parse(make(), config(classification_fields=CLASSIFICATION_FIELDS))
        self.assertEqual(r.unclassified_fields, ["code_1", "identifier_1", "identifier_3"])
        self.assertTrue(all("is empty" in w.message for w in r.warnings))

    def test_an_error_still_makes_the_line_invalid(self):
        r = parse(make(code_1="XYZ", n1="+3"), self.LISTS)
        self.assertEqual((r.parse_status, r.unclassified_fields), (INVALID, ["code_1"]))

    def test_the_lists_are_never_shown(self):
        secret = config(code_1_values=("ABC",), identifier_1_values=("SECRET1",), identifier_2_values=("SECRET2",),
                        identifier_3_states=("SECRET7",),
                        identifier_3_values=("SECRET3",), identifier_3_keywords=("SECRET4",),
                        anomaly_lines={"I am SECRET5": "SOME_LINE"}, identifier_2_with_symbols=("SECRET&6",),
                        classification_fields=CLASSIFICATION_FIELDS)
        for strict in (False, True):
            r = parse(make(id1="OTHER1", id2="OTHER2", id3="OTHER3"), dataclasses.replace(secret, strict_mode=strict))
            messages = " ".join(i.message for i in r.warnings + r.errors)
            self.assertIn("IDENTIFIER_3_VALUES", messages)
            self.assertNotIn("SECRET", messages)
        public = json.dumps(secret.to_public_dict())
        self.assertNotIn("SECRET", public)
        self.assertEqual(secret.to_public_dict()["identifier_3_values"], "1 values (not shown)")
        self.assertIn("ABC", public)                                                          # codes are not identifiers


class Configuration(unittest.TestCase):
    def test_defaults_follow_the_answers_and_the_sample(self):
        d = ParserConfig()
        self.assertEqual((d.line_width, d.century, d.utc_offset, d.strict_mode, d.number_pattern), (132, 2000, "+08:00", False, r"-?\d+(?:\.\d+)?"))
        self.assertEqual(d.columns["identifier_2"], (46, 55))
        self.assertEqual(d.optional_fields, ("numeric_triplet", "code_1", "code_2", "identifier_1", "identifier_2", "location",
                                             "identifier_3", "unit_or_type", "number_1", "number_2", "state", "limit_code"))
        self.assertEqual((d.classification_fields, d.code_2_values, d.identifier_2_values, d.no_unit_markers),
                         (("code_1", "identifier_1", "identifier_3"), (), (), ("-",)))

    def test_from_dict(self):
        loaded = ParserConfig.from_dict({**NEUTRAL, "identifier_1_values": ["PUMP"], "allowed_states": ["RUN"]})
        self.assertEqual((loaded.identifier_1_values, loaded.allowed_states), (("PUMP",), ("RUN",)))
        self.assertEqual(ParserConfig.from_dict(json.loads(json.dumps(loaded.to_dict()))), loaded)
        for bad in ({"no_such_setting": 1}, {"century": 1950}, {"code_1_pattern": "["}, {"utc_offset": "8"},
                    {"optional_fields": ["colour"]}, {"expected_month": "Oct 26"}, {"classification_fields": ["state"]},
                    {"identifier_3_keywords": ["Live", " "]}, {"message_prefixes": [""]},
                    {"anomaly_lines": {" ": "X"}}, {"anomaly_lines": {" Line": "X"}}, {"anomaly_lines": {"Line": "not a code"}},
                    {"state_spellings": {" ": "POWCON"}}, {"state_spellings": {"cPOWCON": "powcon"}},
                    {"identifier_2_with_symbols": ["A&B C"]}, {"identifier_2_with_symbols": [""]},
                    {"columns": {**COLUMNS, "date": (2, 12)}}, {"columns": {"date": (2, 10)}},
                    {"reading_columns": {**READING_COLUMNS, "number_2": (96, 110)}}):
            with self.assertRaises(ValueError, msg=bad):
                ParserConfig.from_dict(bad)

    def test_the_layout_can_change(self):
        wider = config(line_width=134)
        self.assertEqual(parse(make() + "  ", wider).parse_status, PARSED)
        self.assertIn("UNEXPECTED_LINE_WIDTH", codes(parse(make(), wider)))
        narrow = config(columns={**COLUMNS, "limit_code": (116, 118)})                      # the limit code alone again
        self.assertIn("EXTRA_TRAILING_CONTENT", codes(parse(make(over=((119, "ackd"),)), narrow)))

    def test_new_values_by_configuration(self):
        extended = config(allowed_states=STATES + ("ACK",), allowed_units=UNITS + ("KPA",), strict_mode=True)
        r = parse(make(state="ACK", unit="KPA"), extended)
        self.assertEqual((r.parse_status, r.state, r.unit_or_type), (PARSED, "ACK", "KPA"))


class Devices(unittest.TestCase):
    """event_log_devices.py: a device (one signal) is classified by the group of states it shows."""

    GROUPS = [("ON", "OFF"), ("RUN", "STOP"), ("START", "STOP"), ("OK", "FAULT"), ("01", "02", "03", "04", "05", "06")]

    def test_the_group_its_states_fall_in_classifies_a_device(self):
        cases = {("ON", "OFF"): ("grouped", "ON/OFF"), ("ON",): ("grouped", "ON/OFF"),
                 ("01", "03", "06"): ("grouped", "01/02/03/04/05/06"), ("STOP",): ("ambiguous", ""),
                 ("LOCAL", "REMOTE"): ("ungrouped", ""), ("ON", "OFF", "FAULT"): ("mixed", ""), (): ("no_state", "")}
        for states, expected in cases.items():
            self.assertEqual(classify(states, self.GROUPS)[:2], expected, states)
        self.assertIn("RUN/STOP, START/STOP", classify({"STOP"}, self.GROUPS)[2])
        self.assertIn("LOCAL, REMOTE", classify({"LOCAL", "REMOTE"}, self.GROUPS)[2])
        self.assertIn("FAULT in OK/FAULT", classify({"ON", "OFF", "FAULT"}, self.GROUPS)[2])

    def test_the_other_states_of_a_state(self):
        self.assertEqual([other_states(s, self.GROUPS) for s in ("ON", "STOP", "03", "APP")],
                         [("OFF",), ("RUN", "START"), ("01", "02", "04", "05", "06"), ()])
        self.assertEqual(len(other_states("03")), 19)                                          # Transformer: 01 to 20

    def test_a_named_group_names_the_type(self):
        self.assertEqual(classify({"03", "17"})[:2], ("grouped", "Transformer"))
        self.assertEqual(classify({"ON", "OFF"})[:2], ("grouped", "ON/OFF"))
        self.assertEqual(classify({"03", "ON"})[:2], ("mixed", ""))

    def test_the_groups_are_checked(self):
        checked = check_groups(STATE_GROUPS)                                                     # the groups as filled in
        self.assertEqual(checked["Transformer"], tuple(f"{n:02d}" for n in range(1, 21)))      # 01 to 20
        self.assertEqual(check_groups([("ON", "OFF")]), {"ON/OFF": ("ON", "OFF")})            # a list: named by its states
        for bad in ([("ON",)], [("ON", "ON")], [("ON", "NOPE")], [("on", "off")], [("ON", "OFF"), ("OFF", "ON")],
                    {" ": ("ON", "OFF")}, {"A": ("ON", "OFF"), "B": ("OFF", "ON")}):
            with self.assertRaises(ValueError, msg=bad):
                check_groups(bad)

    def test_a_folder_of_events(self):
        lines = [make(state="ON"), make(state="OFF"), make(state="ON"), make(id3="ID004", state="LOCAL"),
                 make(id3="ID004", state="REMOTE"), make(id3="ID005", state="STOP"), make(id3="ID006", state="", limit=""),
                 make(id3="ID004", state="ON OFF")]                                            # the last: invalid
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.assertEqual(event_log_devices.main(["--output", name, "--quiet"]), 1)          # no events file yet
            with (folder / "event_log_events_2026-10.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=event_log.EVENT_COLUMNS)
                writer.writeheader()
                for number, line in enumerate(lines, start=1):
                    writer.writerow({"folder_month": "2026-10", **parse_line(line, number, "x.log.gz", CONFIG).to_row()})
            result = event_log_devices.classify_folder(folder, self.GROUPS)
            self.assertEqual((result["months"], result["lines"], result["lines_left_out"], result["devices"]),
                             (["2026-10"], 7, {"invalid": 1}, 4))
            self.assertEqual(result["statuses"], {"grouped": 1, "ungrouped": 1, "ambiguous": 1, "no_state": 1})
            self.assertEqual(result["groups"], {"ON/OFF": 1})

            def read(file):
                with (folder / file).open(encoding="utf-8", newline="") as handle:
                    return list(csv.DictReader(handle))
            devices = read("event_log_devices.csv")
            self.assertEqual([(d["identifier_3"], d["lines"], d["states"], d["status"], d["state_group"]) for d in devices],
                             [("ID003", "3", "OFF 1; ON 2", "grouped", "ON/OFF"), ("ID004", "2", "LOCAL 1; REMOTE 1", "ungrouped", ""),
                              ("ID005", "1", "STOP 1", "ambiguous", ""), ("ID006", "1", "", "no_state", "")])
            self.assertEqual((devices[0]["code_1"], devices[0]["location"]), ("ABC", "Main Plant Room"))
            self.assertEqual([d["identifier_3"] for d in read("event_log_devices_review.csv")], ["ID004", "ID005", "ID006"])
            self.assertEqual([(s["states"], s["devices"], s["lines"], s["status"]) for s in read("event_log_state_sets.csv")],
                             [("LOCAL/REMOTE", "1", "2", "ungrouped"), ("STOP", "1", "1", "ambiguous")])
            counts = json.loads((folder / "event_log_devices_summary.json").read_text(encoding="utf-8"))
            self.assertEqual((counts["state_groups"], counts["groups"], counts["devices"]),
                             (["ON/OFF", "RUN/STOP", "START/STOP", "OK/FAULT", "01/02/03/04/05/06"], {"ON/OFF": 1}, 4))
            self.assertNotIn("ID003", json.dumps(counts))                                        # counts only
            self.assertEqual(event_log_devices.main(["--output", name, "--quiet"]), 0)          # alone, with the groups filled in


class Samples(unittest.TestCase):
    """The synthetic samples parse to their expected outputs (with event_log_samples/sample_config.json)."""

    def test_samples(self):
        folder = HERE / "event_log_samples"
        settings = ParserConfig.from_file(folder / "sample_config.json")
        logs = sorted(folder.glob("*.log"))
        self.assertTrue(logs)
        for path in logs:
            expected = json.loads((folder / f"{path.stem}.expected.json").read_text(encoding="utf-8"))
            lines = path.read_bytes().decode("utf-8").split("\n")[:-1]
            got = [parse_line(line, i, path.name, settings).to_dict() for i, line in enumerate(lines, start=1)]
            self.assertEqual(got, expected, path.name)


class Run(unittest.TestCase):
    """event_log.py over <root>/<Mmm YY>/*.gz and <root>/<YYYY>/<Mmm YY>/*.gz."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        base = Path(self.folder.name)
        self.root, self.out, self.config = base / "event_logs", base / "out", base / "config.json"
        self.config.write_text(json.dumps(CONFIG.to_dict()), encoding="utf-8")
        oct26, dec25 = self.root / "Oct 26", self.root / "2025" / "Dec 25"
        for folder in (oct26, dec25, self.root / "2025" / "decembre 25", self.root / "2025" / "Jan 26", self.root / "notes",
                       self.root / "Sepx 25"):
            folder.mkdir(parents=True)
        with gzip.open(oct26 / "a.log.gz", "wb") as handle:
            handle.write((make(eol="\n") + make(date="20/10/26", state="RUNNING", eol="\n") + make(date="01/11/26", eol="\n")).encode("utf-8"))
        with gzip.open(dec25 / "b.log.gz", "wb") as handle:
            handle.write(make(date="31/12/25", eol="\n").encode("utf-8") + b"A 31/12/25 \xff\xfe broken\n")
        complete = gzip.compress(make(date="21/10/26", eol="\n").encode("utf-8") * 50)
        (oct26 / "c.log.gz").write_bytes(complete[:len(complete) // 2])                       # cut off half way
        (dec25 / "notes.txt").write_text("not a log", encoding="utf-8")
        (self.root / "readme.txt").write_text("not a log", encoding="utf-8")

    def tearDown(self):
        self.folder.cleanup()

    def rows(self, month):
        with (self.out / f"event_log_events_{month}.csv").open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def run_it(self, *extra, settings=None, quiet=True):
        if settings is not None:
            self.config.write_text(json.dumps(settings.to_dict()), encoding="utf-8")
        return event_log.main(["--root", str(self.root), "--output", str(self.out), "--config", str(self.config),
                               *(["--quiet"] if quiet else []), *extra])

    def test_every_line_every_file_and_every_reason(self):
        self.assertEqual(self.run_it(), 0)
        summary = json.loads((self.out / "event_log_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(list(summary["months"]), ["2025-12", "2026-10"])                    # with or without a year folder
        devices = summary["devices"]                                                          # then the devices, by their states
        self.assertEqual((devices["months"], devices["lines"], devices["lines_left_out"], devices["statuses"]),
                         (["2025-12", "2026-10"], 4, {"invalid": 1}, {"ungrouped": 1}))      # RUN, and RUNNING in no group
        self.assertTrue((self.out / "event_log_state_sets.csv").is_file())
        october = self.rows("2026-10")
        self.assertEqual((october[0]["source_file"], october[0]["line_number"], october[0]["parse_status"], october[0]["timestamp"]),
                         ("Oct 26/a.log.gz", "1", "parsed", "2026-10-19T14:35:02+08:00"))
        self.assertEqual(october[0]["raw_line"], make())
        self.assertEqual((october[1]["parse_status"], october[1]["warning_codes"]), ("parsed_with_warnings", "UNKNOWN_STATE"))
        self.assertEqual(october[2]["warning_codes"], "DATE_OUTSIDE_FOLDER_MONTH")
        self.assertEqual(summary["months"]["2026-10"]["file_errors"][0]["file"], "Oct 26/c.log.gz")
        december = self.rows("2025-12")
        self.assertEqual([r["parse_status"] for r in december], ["parsed", "invalid"])
        issues = [json.loads(line) for line in (self.out / "event_log_issues_2025-12.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(issues[0]["errors"][0]["code"], "INVALID_ENCODING")
        reasons = {s["path"]: s["reason"] for s in summary["skipped"]}
        self.assertEqual(set(reasons), {"readme.txt", "notes", "Sepx 25", "2025/decembre 25", "2025/Jan 26", "2025/Dec 25/notes.txt"})
        self.assertIn("does not match the year folder", reasons["2025/Jan 26"])
        # every line no rule covers, for review: the unknown state, the date from November, the undecodable line
        with (self.out / "event_log_exceptions_2026-10.csv").open(encoding="utf-8", newline="") as handle:
            review = list(csv.DictReader(handle))
        self.assertEqual([(r["line_number"], r["exception_codes"]) for r in review],
                         [("2", "UNKNOWN_STATE"), ("3", "DATE_OUTSIDE_FOLDER_MONTH")])
        self.assertEqual(review[0]["raw_line"], make(date="20/10/26", state="RUNNING"))
        with (self.out / "event_log_exceptions_2025-12.csv").open(encoding="utf-8", newline="") as handle:
            self.assertEqual([r["exception_codes"] for r in csv.DictReader(handle)], ["INVALID_ENCODING"])
        with (self.out / "event_log_exceptions_paths.csv").open(encoding="utf-8", newline="") as handle:
            paths = {r["path"]: r["what"] for r in csv.DictReader(handle)}
        self.assertEqual(paths["Sepx 25"], "left out")
        self.assertEqual(paths["Oct 26/c.log.gz"], "damaged archive")
        self.assertEqual(summary["exceptions"], {"lines": 3, "paths": 7})

    def test_unclassified_lines_and_what_to_add(self):
        lists = config(code_1_values=("ABC",), identifier_1_values=("ID001",), identifier_3_values=("ID003",),
                       classification_fields=CLASSIFICATION_FIELDS)
        lines = [("ABC", "ID001", "ID003"), ("PLC", "ID001", "ID003"), ("PLC", "TAG10", "ID003"), ("ABC", "ID001", "FAN 9"),
                 ("PLC", "ID001", "FAN 9")]
        with gzip.open(self.root / "Oct 26" / "d.log.gz", "wb") as handle:
            handle.write(("".join(make(date="22/10/26", code_1=c, id1=i1, id3=i3, eol="\n") for c, i1, i3 in lines)
                          + make(date="22/10/26", id3="operator1", reading=False, eol="\n")).encode("utf-8"))
        self.assertEqual(self.run_it("--months", "Oct 26", settings=lists), 0)
        october = [r for r in self.rows("2026-10") if r["source_file"].endswith("d.log.gz")]
        self.assertEqual([r["parse_status"] for r in october],
                         ["parsed", "unclassified", "unclassified", "unclassified", "unclassified", "parsed"])
        self.assertEqual(october[4]["unclassified_fields"], "code_1;identifier_3")
        self.assertEqual((october[5]["user_name"], october[5]["identifier_3"]), ("operator1", ""))      # the events file only
        with (self.out / "event_log_unclassified_values.csv").open(encoding="utf-8", newline="") as handle:
            to_add = list(csv.DictReader(handle))
        self.assertEqual({(r["field"], r["value"]): int(r["lines"]) for r in to_add},
                         {("code_1", "PLC"): 3, ("identifier_3", "FAN 9"): 2, ("identifier_1", "TAG10"): 1})
        self.assertEqual((to_add[0]["field"], to_add[0]["value"]), ("code_1", "PLC"))         # the most lines first
        summary = json.loads((self.out / "event_log_summary.json").read_text(encoding="utf-8"))
        self.assertEqual((summary["unclassified"]["lines"], summary["unclassified"]["values_to_add"]),
                         (4, {"code_1": 1, "identifier_1": 1, "identifier_3": 1}))
        self.assertNotIn("ID001", json.dumps(summary["config"]))                             # identifier lists: counts only
        self.assertEqual(summary["totals"]["user_name_lines"], 1)
        self.assertNotIn("operator1", json.dumps(summary))                                   # user names: counts only

    def summary(self, out=None):
        return json.loads(((out or self.out) / "event_log_summary.json").read_text(encoding="utf-8"))

    def outputs(self, out=None):
        """Every output file but the summaries (which hold times and paths), as written."""
        return {p.name: p.read_bytes() for p in sorted((out or self.out).iterdir())
                if p.name not in ("event_log_summary.json", "event_log_devices_summary.json")}

    def test_files_read_in_parallel_give_the_same_outputs(self):
        self.assertEqual(self.run_it("--workers", "1"), 0)                                    # one file after another
        one = self.outputs()
        shutil.rmtree(self.out)
        self.assertEqual(self.run_it("--workers", "2"), 0)                                    # Oct 26's two files at once
        self.assertEqual(self.outputs(), one)                                                 # the same bytes, in file order
        self.assertEqual(self.summary()["months"]["2026-10"]["file_errors"][0]["file"], "Oct 26/c.log.gz")
        self.assertFalse(list(self.out.glob(".event_log_parts_*")))                          # the parts are gone
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            event_log.parse_args(["--workers", "0"])

    def test_a_second_run_reads_nothing_again(self):
        self.assertEqual(self.run_it(), 0)
        first, lines = self.outputs(), self.summary()["totals"]["lines"]
        self.assertEqual(self.run_it(), 0)
        totals = self.summary()["totals"]
        self.assertEqual((totals["read_now"], totals["already_processed"], totals["lines"]), (0, 3, lines))
        self.assertEqual(self.outputs(), first)                                             # every output as it was
        entry = json.loads((self.out / "event_log_processed.json").read_text(encoding="utf-8"))["files"]["Oct 26/a.log.gz"]
        sha = hashlib.sha256((self.root / "Oct 26" / "a.log.gz").read_bytes()).hexdigest()
        self.assertEqual((entry["sha256"], entry["month"], entry["lines"]), (sha, "2026-10", 3))

    def test_only_new_and_changed_files_are_read_and_the_outputs_match_a_full_run(self):
        self.run_it()
        with gzip.open(self.root / "Oct 26" / "0.log.gz", "wb") as handle:                   # new, and first in its month
            handle.write(make(date="23/10/26", state="STOP", eol="\n").encode("utf-8"))
        with gzip.open(self.root / "2025" / "Dec 25" / "b.log.gz", "wb") as handle:           # changed
            handle.write(make(date="30/12/25", eol="\n").encode("utf-8"))
        self.run_it()
        months = self.summary()["months"]
        self.assertEqual({k: (m["read_now"], m["already_processed"]) for k, m in months.items()},
                         {"2025-12": (1, 0), "2026-10": (1, 2)})
        fresh = Path(self.folder.name) / "fresh"
        self.assertEqual(event_log.main(["--root", str(self.root), "--output", str(fresh), "--config", str(self.config), "-q"]), 0)
        self.assertEqual(self.outputs(), self.outputs(fresh))                               # the same as reading everything

    def test_a_repeat_is_left_out(self):
        shutil.copy(self.root / "Oct 26" / "a.log.gz", self.root / "Oct 26" / "copy.log.gz")
        self.run_it()
        sources = [r["source_file"] for r in self.rows("2026-10")]
        self.assertEqual((sources.count("Oct 26/a.log.gz"), sources.count("Oct 26/copy.log.gz")), (3, 0))
        with (self.out / "event_log_exceptions_paths.csv").open(encoding="utf-8", newline="") as handle:
            paths = {r["path"]: (r["what"], r["reason"]) for r in csv.DictReader(handle)}
        self.assertEqual(paths["Oct 26/copy.log.gz"], ("repeat", "the same content as Oct 26/a.log.gz; left out"))
        self.assertEqual(self.summary()["totals"]["repeats"], 1)

    def test_changed_settings_or_missing_outputs_read_again(self):
        self.run_it()
        self.run_it("--strict")                                                             # other settings: every file
        self.assertEqual(self.summary()["totals"]["read_now"], 3)
        (self.out / "event_log_events_2026-10.csv").unlink()                                 # an output gone: its month
        self.run_it("--strict")
        self.assertEqual({k: m["read_now"] for k, m in self.summary()["months"].items()}, {"2025-12": 0, "2026-10": 2})

    def test_options(self):
        self.assertEqual(self.run_it("--strict", "--months", "Oct 26"), 0)
        october = self.rows("2026-10")
        self.assertEqual((october[1]["parse_status"], october[1]["error_codes"]), ("invalid", "INVALID_STATE"))
        self.assertFalse((self.out / "event_log_events_2025-12.csv").exists())

    def test_month_names_in_natural_forms(self):
        for name, number in (("Sep", 9), ("Sept", 9), ("SEPT", 9), ("september", 9), ("June", 6), ("Jul", 7), ("dec", 12)):
            self.assertEqual(event_log.month_number(name), number, name)
        for name in ("Se", "Ju", "Sepx", "Septembre", ""):                                     # three letters at least, of the name
            self.assertIsNone(event_log.month_number(name), name)
        for name, key in (("Dec 25", "2025-12"), ("Sept-25", "2025-09"), ("September-2025", "2025-09"), ("sep_25", "2025-09"),
                          ("SEPT 2025", "2025-09"), ("Sep25", "2025-09"), ("2025-09", None), ("Sept 202", None), ("Sept  25", None)):
            self.assertEqual(event_log.month_key(name), key, name)

    def test_month_folders_in_natural_forms_and_one_month_each(self):
        base = Path(self.folder.name) / "names"
        for folder in ("Sept-25", "2025/September 2025", "Oct 26", "2026/october-26", "2024/Sep-25", "Sepx 25"):
            (base / folder).mkdir(parents=True)
            (base / folder / "a.log.gz").write_bytes(gzip.compress(b""))
        months, skipped = event_log.discover(base)
        self.assertEqual([(m.key, m.label, len(m.files)) for m in months],                   # two folders of one month: one
                         [("2025-09", "September 2025 + Sept-25", 2), ("2026-10", "october-26 + Oct 26", 2)])
        self.assertEqual(sorted(s["path"] for s in skipped), ["2024/Sep-25", "Sepx 25"])

    def test_nothing_to_read_is_a_failure(self):
        empty = Path(self.folder.name) / "empty"
        empty.mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(event_log.main(["--root", str(empty), "--output", str(self.out), "-q"]), 1)
            self.assertEqual(event_log.main(["--root", str(empty / "missing"), "--output", str(self.out), "-q"]), 1)
        self.assertIn("ERROR   | No .gz files under", err.getvalue())                         # errors show, even quiet
        self.assertIn("ERROR   | Run stopped | total runtime", err.getvalue())

    def test_progress_goes_to_stderr_and_never_shows_a_line(self):
        def run(*flags):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.run_it(*flags, quiet=False), 0)
            return err.getvalue()
        normal, verbose, quiet = run(), run("--verbose"), run("--quiet")                    # read all, then none
        self.assertIn("| INFO    | START Oct 26: 2 files", normal)
        self.assertIn("| WARNING | Oct 26/c.log.gz: a damaged archive", normal)
        self.assertRegex(normal, r"\| runtime \d\d:\d\d:\d\d\.\d \|")
        self.assertIn("Run completed | total runtime", normal)
        self.assertNotIn("DEBUG", normal)
        self.assertIn("| DEBUG   | Oct 26/a.log.gz: already processed, not read again (3 rows)", verbose)
        self.assertEqual(quiet, "")                                                          # nothing went wrong
        for text in (normal, verbose):
            for value in (make(), "Main Plant Room", "ID001", "ID003"):                       # never a line or a value
                self.assertNotIn(value, text)

    def test_verbosity_options(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for bad in (["--verbose", "--quiet"], ["--progress-interval", "0"], ["--progress-interval", "inf"]):
                with self.assertRaises(SystemExit, msg=bad):
                    event_log.parse_args(bad)
        args = event_log.parse_args(["-v", "--progress-interval", "5"])
        self.assertEqual((args.verbose, args.quiet, args.progress_interval), (True, False, 5.0))


if __name__ == "__main__":
    unittest.main()
