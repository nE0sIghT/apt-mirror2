from pathlib import Path

from apt_mirror.apt_mirror import PathCleaner
from tests.base import BaseTest


class TestRepository(BaseTest):
    def test_wipe_threashold(self):
        clean_path = self.TEST_DATA / "PathClean"

        cleaner = PathCleaner(
            clean_path, set(), wipe_size_ratio=0, wipe_count_ratio=0.6
        )

        self.assertFalse(
            cleaner._clean_allowed()  # pylint: disable=W0212 # type: ignore
        )

        cleaner = PathCleaner(
            clean_path, set(), wipe_size_ratio=0.6, wipe_count_ratio=0
        )

        self.assertFalse(
            cleaner._clean_allowed()  # pylint: disable=W0212 # type: ignore
        )

        cleaner = PathCleaner(
            clean_path, {Path("1")}, wipe_size_ratio=0.7, wipe_count_ratio=0
        )

        self.assertTrue(
            cleaner._clean_allowed()  # pylint: disable=W0212 # type: ignore
        )
        cleaner = PathCleaner(
            clean_path, {Path("1")}, wipe_size_ratio=0, wipe_count_ratio=0.7
        )

        self.assertTrue(
            cleaner._clean_allowed()  # pylint: disable=W0212 # type: ignore
        )
