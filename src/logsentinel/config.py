from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    ls001_min_unique_users: int = 3
    ls001_time_window_seconds: int = 60

    ls002_min_failed_attempts: int = 5
    ls002_time_window_seconds: int = 60

    def __post_init__(self):
        for field_name in (
            "ls001_min_unique_users",
            "ls001_time_window_seconds",
            "ls002_min_failed_attempts",
            "ls002_time_window_seconds",
        ):
            value = getattr(self, field_name)

            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{field_name} must be a positive integer"
                )

