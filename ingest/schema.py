"""The one normalised record every parser produces.

Field *names* in the incoming data come from config.yaml's schema map — NTRO's
keys may differ from our synthetic ones — but every parser hands this model the
same canonical keys.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, ValidationError, model_validator


class RawTransaction(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    timestamp: datetime
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    txid: str = Field(min_length=1)
    input_addresses: list[str]
    output_addresses: list[str]
    input_amounts: list[float]
    output_amounts: list[float]
    fee: float = Field(ge=0)
    script_type: str = ""
    # The NTRO schema carries these; we keep them as a fallback for when the
    # local GeoIP databases are unavailable. geoip.py records which won.
    asn: int | None = None
    geo_country: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> RawTransaction:
        if len(self.input_addresses) != len(self.input_amounts):
            raise ValueError("mismatched input array lengths")
        if len(self.output_addresses) != len(self.output_amounts):
            raise ValueError("mismatched output array lengths")
        if not self.input_addresses or not self.output_addresses:
            raise ValueError("transaction has no inputs or no outputs")
        if any(a < 0 for a in self.input_amounts + self.output_amounts):
            raise ValueError("negative amount")
        return self


# Validation errors are turned into one short, greppable reason per record so
# quarantine stays analysable instead of holding pydantic tracebacks.
_REASONS = {
    "ip_any_address": "bad IP",
    "datetime_from_date_parsing": "bad timestamp",
    "datetime_type": "bad timestamp",
    "float_parsing": "bad amount",
    "int_parsing": "bad port",
    "greater_than_equal": "negative value",
    "less_than_equal": "port out of range",
    "missing": "missing field",
    "float_type": "not a number",
    "int_type": "not a number",
    "string_type": "not text",
    "list_type": "not a list",
    "string_too_short": "empty field",
}


def reason_for(exc: ValidationError) -> str:
    reasons = []
    for err in exc.errors():
        field = ".".join(str(p) for p in err["loc"]) or "record"
        if err["type"] == "value_error":
            reasons.append(str(err.get("ctx", {}).get("error", err["msg"])))
        else:
            reasons.append(f"{_REASONS.get(err['type'], err['type'])}: {field}")
    return "; ".join(dict.fromkeys(reasons))


def validate(record: dict[str, Any]) -> tuple[RawTransaction | None, str | None]:
    """Returns (model, None) or (None, reason). Never raises on bad input."""
    try:
        return RawTransaction.model_validate(record), None
    except ValidationError as exc:
        return None, reason_for(exc)
    except Exception as exc:  # a parser handed us something unusable
        return None, f"unparseable: {type(exc).__name__}: {exc}"
