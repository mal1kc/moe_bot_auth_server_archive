from __future__ import annotations

import logging
from typing import Any, Dict

from pytest import fixture

from moe_bot_auth_server.data_schema_validation import And, Schema, SchemaValidationError

LOGGER = logging.getLogger("data_schema_validation_test")


"""
not finished code
"""


@fixture
def validation_schema() -> Schema:
    return Schema(
        {
            "name": And(str, len),
            "age": And(int, lambda n: 18 <= n <= 99),
            "profession": And(str, len),
            "Adress": {
                "street": And(str, len),
                "number": And(int, lambda n: 1 <= n <= 9999),
                "city": And(str, len),
            },
        }
    )


@fixture
def valid_data() -> Dict[str, Any]:
    return {
        "name": "Sue",
        "age": 28,
        "profession": "Software developer",
        "Adress": {"street": "Example Street", "number": 123, "city": "Example City"},
    }


@fixture
def invalid_data() -> Dict[str, Any]:
    return {
        "name": "Sue",
        "age": 1.5,
        "profession": {"years": 3},
        "Adress": {"street": 12, "number": "123", "city": 41},
    }


def test_valid_data(validation_schema: Schema, valid_data: Dict[str, Any]) -> None:
    assert validation_schema.validate(valid_data)


def test_invalid_data(validation_schema: Schema, invalid_data: Dict[str, Any]) -> None:
    try:
        validation_schema.validate(invalid_data)
    except SchemaValidationError as e:
        LOGGER.info(e)
        assert "age" not in e.errors  # age is valid
        assert "profession" not in e.errors
        assert "Adress" not in e.errors
        assert "street" not in e.errors
        assert "number" not in e.errors
        assert "city" not in e.errors
