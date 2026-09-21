import pytest

import config


def test_schema_remap():
    assert config.field("tx_id") == config.load()["schema"]["tx_id"]


def test_dotted_get():
    assert config.get("risk_weights.rules") == config.load()["risk_weights"]["rules"]
    with pytest.raises(KeyError):
        config.get("risk_weights.nope")


def test_weights_sum_to_one():
    assert sum(config.get("risk_weights").values()) == pytest.approx(1.0)
