from pathlib import Path
from typing import Iterable

from apt_mirror.download import DownloadFile
from apt_mirror.download.url import URL
from apt_mirror.repository import (
    ByHash,
    Codename,
    InvalidReleaseFilesException,
    Repository,
)
from tests.base import BaseTest


class TestRepository(BaseTest):
    @staticmethod
    def get_from_set(collection: Iterable[DownloadFile], element: Path) -> DownloadFile:
        for e in collection:
            if hash(e) == hash(element):
                return e

        raise RuntimeError(f"No element {element} found in set {collection}")

    def get_repository(self):
        components = ["main", "contrib", "non-free"]

        return Repository(
            url=URL.from_string("http://localhost.local/repo"),
            clean=False,
            skip_clean=set(),
            mirror_path=Path("repo"),
            ignore_errors=set(),
            codenames=Repository.Codenames(
                [
                    (
                        "test",
                        Codename(
                            ByHash.default(),
                            "test",
                            {
                                component: Codename.Component("main", True, ["amd64"])
                                for component in components
                            },
                        ),
                    )
                ]
            ),
        )

    def test_ignore_errors(self):
        config = self.get_config("IgnoreErrorsConfig")

        repository = self.ensure_repository(
            config.repositories[
                "https://packages.gitlab.com/runner/gitlab-runner/debian"
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
            config.repositories["http://ftp.debian.org/debian-security"]
        )
        self.assertFalse(repository.ignore_errors)

    def test_release_files(self):
        repository = self.get_repository()

        with self.assertRaises(InvalidReleaseFilesException):
            repository.validate_release_files(
                self.TEST_DATA / "UnsyncedReleaseFiles", False
            )

        repository.validate_release_files(self.TEST_DATA / "SyncedReleaseFiles", False)

        with self.assertRaises(InvalidReleaseFilesException):
            repository.validate_release_files(
                self.TEST_DATA / "NonExistingFolder", False
            )
