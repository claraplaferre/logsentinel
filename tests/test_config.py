import pytest

from src.logsentinel.config import DetectionConfig


def test_default_configuration():
    config = DetectionConfig()

    assert config.ls001_min_unique_users == 3
    assert config.ls001_time_window_seconds == 60
    assert config.ls002_min_failed_attempts == 5
    assert config.ls002_time_window_seconds == 60


@pytest.mark.parametrize(
    "field_name",
    [
        "ls001_min_unique_users",
        "ls001_time_window_seconds",
        "ls002_min_failed_attempts",
        "ls002_time_window_seconds",
    ],
)
def test_rejects_invalid_configuration(field_name):
    with pytest.raises(ValueError):
        DetectionConfig(**{field_name: -1})
