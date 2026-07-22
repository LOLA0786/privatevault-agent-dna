"""The JSON log formatter must not crash on a normal LogRecord.

Reproduced from an external release audit: the formatter did
record.update(record.extra), but LogRecord has no .extra attribute --
Python stores extras as top-level attrs, not a dict. Any log call that
reached this line raised AttributeError.
"""

import logging

from agent_dna.observability.logger import JSONFormatter


def _record(**extra):
    r = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
    for k, v in extra.items():
        setattr(r, k, v)
    return r


def test_plain_record_formats_without_crashing():
    # a normal record has no .extra attribute at all
    out = JSONFormatter().format(_record())
    assert "msg" in out


def test_dict_extra_is_merged_when_present():
    r = _record()
    r.extra = {"request_id": "req-1"}
    out = JSONFormatter().format(r)
    assert "req-1" in out
