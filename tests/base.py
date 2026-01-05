import tempfile
from collections.abc import Sequence
from pathlib import Path
from string import Template
from unittest import TestCase

from apt_mirror.config import Config
from apt_mirror.repository import BaseRepository, FlatRepository, Repository


class BaseTest(TestCase):
    TEST_DATA = Path(__file__).parent / "data"
    DEB822_TEST_DATA = TEST_DATA / "Deb822"
    maxDiff = None

    def get_config(
        self,
        name: str | None = None,
        config_name: str = "mirror.list",
        substitute: dict[str, str] | None = None,
        deb822_names: Sequence[str] | None = None,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            mirror_list = Path(tmp) / config_name

            if name:
                config_path = self.TEST_DATA / name / config_name

                with (
                    mirror_list.open("wt", encoding="utf-8") as fp,
                    config_path.open("rt", encoding="utf-8") as config,
                ):
                    data = config.read()
                    if substitute:
                        data = Template(data).substitute(substitute)

                    fp.write(data)
            else:
                mirror_list.touch()

                if not deb822_names:
                    raise RuntimeError(
                        "Both `name` and `deb822_names` must not be empty"
                    )

            if deb822_names:
                mirror_list_d = mirror_list.with_name(mirror_list.name + ".d")
                mirror_list_d.mkdir()

                for deb822_name in deb822_names:
                    with (
                        open(
                            self.DEB822_TEST_DATA / (deb822_name + ".sources"),
                            "rt",
                            encoding="utf-8",
                        ) as input,
                        open(
                            mirror_list_d / (deb822_name + ".sources"),
                            "wt",
                            encoding="utf-8",
                        ) as output,
                    ):
                        data = input.read()
                        if substitute:
                            data = Template(data).substitute(substitute)

                        output.write(data)

            return Config(mirror_list)

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
