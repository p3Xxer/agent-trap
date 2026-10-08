from src.formatting import money
from src.tax import with_tax


def test_with_tax():
    assert with_tax(100, 0.2) == 120.0


def test_money():
    assert money(1234.5) == "$1,234.50"
