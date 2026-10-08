from src.rates import load_rates


def test_rates_have_usd():
    assert load_rates()["USD"] == 1.0
