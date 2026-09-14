"""Example source for the worked scan."""

import unittest

from app.storage import Record


class RecordTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(Record("a").name, "a")


def load_tests(loader, tests, pattern):
    # Removed in 3.13.
    return unittest.makeSuite(RecordTests)
