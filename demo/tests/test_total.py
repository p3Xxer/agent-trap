from src.invoice import parse_line, total


def test_total():
    assert total([{"name": "a", "qty": 2, "price": 10.0}]) == 20.0


def test_parse():
    assert parse_line("pen,3,5.0")["qty"] == 3
