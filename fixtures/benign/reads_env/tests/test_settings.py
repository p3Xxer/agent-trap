from src.settings import describe


def test_defaults():
    assert describe() == "USD / INFO"
