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

    def get_repository(
        self,
        components: list[str] | None = None,
        arches: list[str] | None = None,
        mirror_source: bool = True,
    ):
        if components is None:
            components = ["main", "contrib", "non-free", "non-free/debian-installer"]

        if arches is None:
            arches = ["amd64", "s390x"]

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
                                component: Codename.Component(
                                    component, mirror_source, arches
                                )
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

    def test_components_filter_buster(self):
        repository = self.get_repository(
            components=["main", "contrib", "non-free", "non-free/debian-installer"],
            arches=["amd64", "s390x"],
            mirror_source=True,
        )

        metadata_files = set(
            d.path.relative_to(Path("dists/test"))
            for d in repository.get_metadata_files(
                self.TEST_DATA / "DebianArchiveBusterProposedUpdates", False, set()
            )
        )

        self.assertIn(Path("main/source/Sources"), metadata_files)
        self.assertIn(Path("main/binary-amd64/Packages"), metadata_files)
        self.assertIn(Path("contrib/binary-amd64/Packages"), metadata_files)
        self.assertIn(Path("contrib/i18n/Translation-en"), metadata_files)
        self.assertIn(Path("non-free/binary-all/Packages"), metadata_files)
        self.assertIn(
            Path("non-free/debian-installer/binary-all/Release"), metadata_files
        )

        self.assertNotIn(Path("main/Contents-ppc64el"), metadata_files)
        self.assertNotIn(Path("contrib/binary-arm64/Packages"), metadata_files)
        self.assertNotIn(Path("non-free-firmware/Contents-amd64"), metadata_files)

        repository = self.get_repository(
            components=["contrib"],
            arches=["i386"],
            mirror_source=False,
        )

        metadata_files = set(
            d.path.relative_to(Path("dists/test"))
            for d in repository.get_metadata_files(
                self.TEST_DATA / "DebianArchiveBusterProposedUpdates", False, set()
            )
        )

        self.assertNotIn(Path("main/source/Sources"), metadata_files)
        self.assertNotIn(Path("contrib/source/Sources"), metadata_files)

        self.assertIn(Path("contrib/binary-all/Packages"), metadata_files)

        self.assertNotIn(Path("main/binary-amd64/Packages"), metadata_files)
        self.assertIn(Path("contrib/binary-i386/Packages"), metadata_files)

    def test_components_filter_bookworm(self):
        repository = self.get_repository(
            components=["main", "contrib", "non-free", "non-free/debian-installer"],
            arches=["amd64", "s390x"],
            mirror_source=True,
        )

        metadata_files = set(
            d.path.relative_to(Path("dists/test"))
            for d in repository.get_metadata_files(
                self.TEST_DATA / "DebianBookworm", False, set()
            )
        )

        self.assertIn(Path("main/Contents-all"), metadata_files)
        self.assertIn(Path("main/Contents-udeb-all"), metadata_files)
        self.assertIn(Path("main/Contents-amd64"), metadata_files)
        self.assertIn(Path("main/Contents-udeb-amd64"), metadata_files)
        self.assertIn(Path("main/Contents-s390x"), metadata_files)
        self.assertIn(Path("main/Contents-udeb-s390x"), metadata_files)

        self.assertNotIn(Path("main/Contents-mips64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-mips64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-ppc64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-ppc64el"), metadata_files)

    def test_components_filter_all(self):
        repository = self.get_repository(
            components=["main", "contrib", "non-free", "non-free/debian-installer"],
            arches=[],
            mirror_source=True,
        )

        metadata_files = set(
            d.path.relative_to(Path("dists/test"))
            for d in repository.get_metadata_files(
                self.TEST_DATA / "DebianBookworm", False, set()
            )
        )

        self.assertNotIn(Path("main/Contents-all"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-all"), metadata_files)
        self.assertNotIn(Path("main/Contents-amd64"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-amd64"), metadata_files)
        self.assertNotIn(Path("main/Contents-s390x"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-s390x"), metadata_files)
        self.assertNotIn(Path("main/Contents-mips64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-mips64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-udeb-ppc64el"), metadata_files)
        self.assertNotIn(Path("main/Contents-ppc64el"), metadata_files)

        self.assertNotIn(Path("main/binary-all/Packages"), metadata_files)

    def test_release_gpg(self):
        repository = self.get_repository(
            components=["main", "contrib", "non-free", "non-free/debian-installer"],
            arches=[],
            mirror_source=True,
        )

        try:
            repository.get_metadata_files(
                self.TEST_DATA / "BinaryGPGReleaseFile", False, set()
            )
        except UnicodeDecodeError:
            self.fail(
                "get_metadata_files() must not raise UnicodeDecodeError in case"
                " Release.gpg is binary"
            )
