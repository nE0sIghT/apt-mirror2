from pathlib import Path
from unittest import TestCase

from apt_mirror.config import Config
from apt_mirror.repository import BaseRepository, FlatRepository, Repository


class BaseTest(TestCase):
    TEST_DATA = Path(__file__).parent / "data"

    def get_config(self, name: str):
        return Config(self.TEST_DATA / name / "mirror.list")

    def ensure_repository(self, repository: BaseRepository) -> Repository:
        if not isinstance(repository, Repository):
            self.assertIsInstance(repository, Repository)
            raise RuntimeError(
                f"{repository.url} repository is not Repository instance"
            )

        return repository

    def ensure_flat_repository(self, repository: BaseRepository) -> FlatRepository:
        if not isinstance(repository, FlatRepository):
            self.assertIsInstance(repository, FlatRepository)
            raise RuntimeError(
                f"{repository.url} repository is not FlatRepository instance"
            )

        return repository
