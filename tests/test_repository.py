from pathlib import Path
from typing import Iterable

from apt_mirror.download import URL, DownloadFile
from tests.base import BaseTest


class TestRepository(BaseTest):
    @staticmethod
    def get_from_set(collection: Iterable[DownloadFile], element: Path) -> DownloadFile:
        for e in collection:
            if hash(e) == hash(element):
                return e

        raise RuntimeError(f"No element {element} found in set {collection}")

    def test_ignore_errors(self):
        config = self.get_config("IgnoreErrorsConfig")

        repository = self.ensure_repository(
            config.repositories[
                URL.from_string(
                    "https://packages.gitlab.com/runner/gitlab-runner/debian"
                )
            ]
        )

        self.assertTrue(repository.ignore_errors)

        files = repository.get_pool_files(
            self.TEST_DATA / "IgnoreErrorsConfig", False, set()
        )

        file = self.get_from_set(
            files,
            Path("pool/bullseye/main/g/gitlab-runner/gitlab-runner_14.8.1_amd64.deb"),
        )
        self.assertTrue(file.ignore_errors)

        file = self.get_from_set(
            files,
            Path("pool/bullseye/main/g/gitlab-runner/gitlab-runner_16.8.0_amd64.deb"),
        )
        self.assertFalse(file.ignore_errors)

        repository = self.ensure_repository(
            config.repositories[
                URL.from_string("http://ftp.debian.org/debian-security")
            ]
        )
        self.assertFalse(repository.ignore_errors)
