import tempfile
from pathlib import Path
from unittest import TestCase

from apt_mirror.config import Config
from apt_mirror.repository import BaseRepository, FlatRepository, Repository


class BaseTest(TestCase):
    TEST_DATA = Path(__file__).parent / "data"

    def get_config(self, name: str, config_name: str = "mirror.list"):
        return Config(self.TEST_DATA / name / config_name)

    def get_modified_config(
        self, name: str, extra: str, config_name: str = "mirror.list"
    ):
        with tempfile.NamedTemporaryFile("wt", encoding="utf-8") as tmp:
            with open(
                self.TEST_DATA / name / config_name, "rt", encoding="utf-8"
            ) as fp:
                tmp.write(fp.read())
                tmp.write("\n")
                tmp.write(extra)

            tmp.flush()

            return Config(Path(tmp.name))

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
