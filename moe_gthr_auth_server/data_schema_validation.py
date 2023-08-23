"""
very basic dict validator
uses a dict schema to validate a dict

example:
    dict_schema = {
        # it will use str to validate the type and len to validate the length
        "name": And(str,Use(len)),
        # it will use int to validate the type and a lambda to validate the value
        "age": And(int, lambda n: 18 <= n <= 99),
        "address": {
            "street": Use(str.upper),  # apply a function to the value
            "city": Use(str.title), #  apply a function to the value
            "state": Use(str),
            "zip": And(Use(int), lambda n: 10000 <= n <= 99999), # apply a function to the value
        }
        "custom_field":  And(Use(str), lambda s: s.startswith('custom_field')), # apply a function to the value
    }
!!!!not_finished!!!!
TODO:
-- possibly multiple changes will be made to this file in the future
-- not used in the project yet
TODO: add more tests
"""
from __future__ import annotations
from typing import Callable, Any, Dict, Iterable, Union, Optional, Type, Set
import logging
import typeguard

LOGGER = logging.getLogger(__name__)


class BaseSchemaValidationError(Exception):
    ...


class SchemaValidationError(BaseSchemaValidationError):
    def __init__(self, *args: object) -> None:
        self.errors: Set = set()
        super().__init__(*args)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.errors=})"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.errors=})"

    def __bool__(self) -> bool:
        return bool(self.errors)

    def __len__(self) -> int:
        return len(self.errors)

    def __iter__(self) -> Iterable[str]:
        return iter(self.errors)

    def __contains__(self, key: str) -> bool:
        return key in self.errors

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, SchemaValidationError):
            return False
        return self.errors == o.errors

    def __ne__(self, o: object) -> bool:
        return not self.__eq__(o)

    def __lt__(self, o: object) -> bool:
        if not isinstance(o, SchemaValidationError):
            return False
        return self.errors < o.errors

    def __le__(self, o: object) -> bool:
        if not isinstance(o, SchemaValidationError):
            return False
        return self.errors <= o.errors

    def __gt__(self, o: object) -> bool:
        if not isinstance(o, SchemaValidationError):
            return False
        return self.errors > o.errors

    def __ge__(self, o: object) -> bool:
        if not isinstance(o, SchemaValidationError):
            return False
        return self.errors >= o.errors

    def __hash__(self) -> int:
        return hash(self.errors) + hash(id(self))

    def __call__(self, error: BaseSchemaValidationError) -> None:
        self.errors.add(error)

    def __raise__(self) -> None:
        if self:
            raise self


class SchemaValidationTypeError(SchemaValidationError):
    pass


class SchemaValidationValueError(SchemaValidationError):
    pass


class Schema:
    def __init__(self, schema_dict: dict[str, And]) -> None:
        self._schema_dict = schema_dict
        self._Error_holder = SchemaValidationError

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._schema_dict=})"

    @property
    def schema_dict(self) -> dict[str, And]:
        return self._schema_dict

    def validate(self, data: dict) -> bool | SchemaValidationError:
        """
        validate the schema

        """
        raise NotImplementedError


class Use(Schema):
    def __init__(self, func: Callable[[Any], Any]) -> None:
        self.func = func

    def __call__(self, value: Any) -> bool:
        if not callable(self.func):
            raise BaseSchemaValidationError(f"{self.func=} is not callable")
        return self.func(value)


class And(Schema):
    def __init__(self, dtype: Type, Use) -> None:
        self.dtype = dtype
        self.func = Use

    def __call__(self, value: Any) -> bool:
        _func_result = self.func(value) if callable(self.func) else None
        if isinstance(value, self.dtype) and _func_result:
            return True
        raise BaseSchemaValidationError(f"{value=} is not {self.dtype=} or function retuns={_func_result}")


class Or(Schema):
    def __init__(self, dtype: Type, Use) -> None:
        self.dtype = dtype
        self.func = Use

    def __call__(self, value: Any) -> bool:
        if isinstance(value, self.dtype):
            return True
        if _func_result := self.func(value):
            return True
        raise BaseSchemaValidationError(f"{value=} is not {self.dtype=} and function retuns={_func_result}")
