"""Example source for the worked scan. Nothing here is fetched from anywhere."""

import datetime


class Record:
    def __init__(self, name: str) -> None:
        self.name = name
        # Deprecated in 3.12: naive UTC is a bug waiting to happen.
        self.created = datetime.datetime.utcnow()

    def age_seconds(self) -> float:
        return (datetime.datetime.utcnow() - self.created).total_seconds()
