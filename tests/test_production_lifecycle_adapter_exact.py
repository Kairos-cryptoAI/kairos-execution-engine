"""Exact venue decimals reach the engine and the journal as decimal text."""

from __future__ import annotations

import json
from decimal import Decimal

from kairos_persistence import canonical_payload

from kairos_execution.production_lifecycle_adapter import _exact_json


def test_exact_decimals_become_their_text_and_are_journal_safe():
    record = {
        "price": Decimal("105.000"),
        "quantity": Decimal("0"),
        "nested": [{"fee": Decimal("123456789012345678.123400")}],
        "id": "tpsl-1",
        "flag": True,
    }
    converted = _exact_json(record)
    assert converted == {
        "price": "105.000",
        "quantity": "0",
        "nested": [{"fee": "123456789012345678.123400"}],
        "id": "tpsl-1",
        "flag": True,
    }
    assert float(converted["price"]) == 105.0
    canonical_payload(converted)  # the execution journal's canonical JSON accepts it
    assert json.loads(json.dumps(converted)) == converted
