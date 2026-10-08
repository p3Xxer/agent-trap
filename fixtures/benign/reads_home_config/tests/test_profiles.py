from src.aws_profiles import list_profiles


def test_profiles_are_a_list():
    assert isinstance(list_profiles(), list)
