from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from apt_mirror.download import DownloadFile
from apt_mirror.download.download_file import FileCompression, HashType
from apt_mirror.download.url import URL
from apt_mirror.filter import PackageFilter
from apt_mirror.repository import (
    ByHash,
    Codename,
    GPGVerify,
    InvalidReleaseFilesException,
    InvalidSignatureError,
    PackagesParser,
    Repository,
    SourcesParser,
    is_safe_path,
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
        mirror_dist_upgrader: bool = False,
        codename: str = "test",
        mirror_path: Path = Path("repo"),
    ):
        if components is None:
            components = ["main", "contrib", "non-free", "non-free/debian-installer"]

        if arches is None:
            arches = ["amd64", "s390x"]

        return Repository(
            url=URL.from_string("http://localhost.local/repo"),
            clean=False,
            skip_clean=set(),
            http2_disable=False,
            mirror_dist_upgrader=mirror_dist_upgrader,
            mirror_path=mirror_path,
            ignore_errors=set(),
            gpg_verify=GPGVerify.default(),
            codenames=Repository.Codenames(
                [
                    (
                        codename,
                        Codename(
                            by_hash=ByHash.default(),
                            signed_by=None,
                            codename=codename,
                            components={
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
            self.TEST_DATA / "IgnoreErrorsConfig", False, True, set()
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
        nonexistent = Path("/a/b/c/d")

        with self.assertRaises(InvalidReleaseFilesException):
            repository.validate_release_files(
                self.TEST_DATA / "UnsyncedReleaseFiles", False, nonexistent, nonexistent
            )

        repository.validate_release_files(
            self.TEST_DATA / "SyncedReleaseFiles", False, nonexistent, nonexistent
        )

        with self.assertRaises(InvalidReleaseFilesException):
            repository.validate_release_files(
                self.TEST_DATA / "NonExistingFolder", False, nonexistent, nonexistent
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

    def test_include_source_name(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror1.list"},
            {"deb822_names": ("bookworm_mirror1",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertEqual(
                    {
                        Path(p)
                        for p in [
                            "pool/main/c/curl/curl_7.88.1-10+deb12u5.debian.tar.xz",
                            "pool/main/c/curl/curl_7.88.1-10+deb12u5.dsc",
                            "pool/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/curl_7.88.1.orig.tar.gz",
                            "pool/main/c/curl/curl_7.88.1.orig.tar.gz.asc",
                            "pool/main/c/curl/libcurl3-gnutls_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/libcurl3-nss_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/libcurl4-doc_7.88.1-10+deb12u5_all.deb",
                            "pool/main/c/curl/libcurl4-gnutls-dev_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/libcurl4-nss-dev_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/libcurl4-openssl-dev_7.88.1-10+deb12u5_amd64.deb",
                            "pool/main/c/curl/libcurl4_7.88.1-10+deb12u5_amd64.deb",
                        ]
                    },
                    files,
                )

    def test_exclude_source_name(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror2.list"},
            {"deb822_names": ("bookworm_mirror2",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                for file in [
                    "pool/main/w/wget/wget_1.21.3-1+b2_amd64.deb",
                    "pool/main/w/wget/wget_1.21.3-1.debian.tar.xz",
                    "pool/main/w/wget/wget_1.21.3-1.dsc",
                    "pool/main/w/wget/wget_1.21.3.orig.tar.gz",
                    "pool/main/w/wget/wget_1.21.3.orig.tar.gz.asc",
                ]:
                    self.assertNotIn(Path(file), files)

    def test_include_source_name_mixed(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror3.list"},
            {"deb822_names": ("bookworm_mirror3",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertEqual(
                    {
                        Path(p)
                        for p in [
                            "pool/main/w/wget/wget_1.21.3-1+b2_amd64.deb",
                            "pool/main/w/wget/wget_1.21.3-1.debian.tar.xz",
                            "pool/main/w/wget/wget_1.21.3-1.dsc",
                            "pool/main/w/wget/wget_1.21.3.orig.tar.gz",
                            "pool/main/w/wget/wget_1.21.3.orig.tar.gz.asc",
                        ]
                    },
                    files,
                )

    def test_exclude_binary_packages(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror4.list"},
            {"deb822_names": ("bookworm_mirror4",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                for file in [
                    "pool/main/w/wget2/libwget0_1.99.1-2.2_amd64.deb",
                    "pool/main/w/wget2/wget2-dev_1.99.1-2.2_amd64.deb",
                ]:
                    self.assertNotIn(Path(file), files)

    def test_include_binary_packages(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror5.list"},
            {"deb822_names": ("bookworm_mirror5",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertEqual(
                    {
                        Path(p)
                        for p in [
                            "pool/main/s/systemd/udev_252.22-1~deb12u1_amd64.deb",
                            "pool/main/w/wget2/libwget0_1.99.1-2.2_amd64.deb",
                            "pool/main/w/wget2/wget2-dev_1.99.1-2.2_amd64.deb",
                        ]
                    },
                    files,
                )

    def test_include_sections(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror6.list"},
            {"deb822_names": ("bookworm_mirror6",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertNotIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertIn("libcurl4-doc_7.88.1-10+deb12u5_all.deb", files)

    def test_exclude_sections(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror7.list"},
            {"deb822_names": ("bookworm_mirror7",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertNotIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertNotIn("libcurl4-doc_7.88.1-10+deb12u5_all.deb", files)

    def test_include_tags(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror8.list"},
            {"deb822_names": ("bookworm_mirror8",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertNotIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertIn("libcurl4-gnutls-dev_7.88.1-10+deb12u5_amd64.deb", files)

    def test_include_facets(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror9.list"},
            {"deb822_names": ("bookworm_mirror9",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertNotIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertIn("systemd-container_252.22-1~deb12u1_amd64.deb", files)

    def test_exclude_tags(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror10.list"},
            {"deb822_names": ("bookworm_mirror10",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertNotIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertNotIn(
                    "libcurl4-gnutls-dev_7.88.1-10+deb12u5_amd64.deb", files
                )

    def test_exclude_facets(self):
        for config_kwargs in [
            {"name": "DebianBookworm", "config_name": "mirror11.list"},
            {"deb822_names": ("bookworm_mirror11",)},
        ]:
            with self.subTest(config_kwargs=config_kwargs):
                config = self.get_config(**config_kwargs)

                repository = self.ensure_repository(
                    config.repositories["http://ftp.debian.org/debian"]
                )
                repository.mirror_path = Path("repo")

                files = {
                    d.path.name
                    for d in repository.get_pool_files(
                        self.TEST_DATA / "DebianBookworm", False, True, set()
                    )
                }

                self.assertIn("curl_7.88.1-10+deb12u5_amd64.deb", files)
                self.assertNotIn("0ad_0.0.26-3_amd64.deb", files)
                self.assertNotIn("systemd-container_252.22-1~deb12u1_amd64.deb", files)

    def test_dist_upgrader(self):
        config = self.get_config("MixedConfig", config_name="mirror1.list")

        repository = self.ensure_repository(
            config.repositories["http://ftp.debian.org/debian"]
        )
        repository.mirror_path = Path("repo")

        files = set(
            f.path
            for f in repository.get_metadata_files(
                self.TEST_DATA / "MixedConfig", False, set()
            )
        )

        base_dist_upgrader_path = Path("dists/bookworm/main/dist-upgrader-all/current")

        self.assertIn(base_dist_upgrader_path / "bookworm.tar.gz", files)
        self.assertIn(base_dist_upgrader_path / "bookworm.tar.gz.gpg", files)

        for file in Repository.DIST_UPGRADER_ANNOUNCEMENTS:
            self.assertIn(
                base_dist_upgrader_path / file,
                files,
            )
            self.assertIn(
                (base_dist_upgrader_path / file).with_suffix(".html"),
                files,
            )

    def test_dist_upgrader_updates(self):
        config = self.get_config("MixedConfig", config_name="mirror1.list")

        repository = self.ensure_repository(
            config.repositories["https://archive.ubuntu.com/ubuntu"]
        )
        repository.mirror_path = Path("repo")

        files = set(
            f.path
            for f in repository.get_metadata_files(
                self.TEST_DATA / "MixedConfig", False, set()
            )
        )

        base_dist_upgrader_path = Path(
            "dists/bionic-updates/main/dist-upgrader-all/current"
        )

        self.assertIn(base_dist_upgrader_path / "bionic.tar.gz", files)
        self.assertIn(base_dist_upgrader_path / "bionic.tar.gz.gpg", files)

        for file in Repository.DIST_UPGRADER_ANNOUNCEMENTS:
            self.assertIn(
                base_dist_upgrader_path / file,
                files,
            )
            self.assertIn(
                (base_dist_upgrader_path / file).with_suffix(".html"),
                files,
            )

    def test_packages_last_stanza(self):
        repository = self.get_repository(["main"], ["amd64"], False)

        files = repository.get_pool_files(
            self.TEST_DATA / "GitlabRegistryPackages", False, True, set()
        )

        single_file = (
            "pool/bullseye/main/g/gitlab-runner/gitlab-runner_14.8.1_amd64.deb"
        )
        self.assertEqual(
            {
                Path(single_file),
            },
            {d.path for d in files},
        )

    def test_sources_last_stanza(self):
        repository = self.get_repository(["main"], [], True)

        files = repository.get_pool_files(
            self.TEST_DATA / "GitlabRegistryPackages", False, True, set()
        )

        single_file = "pool/main/g/gitlab-runner/gitlab-runner_14.8.1.dsc"
        self.assertEqual(
            {
                Path(single_file),
            },
            {d.path for d in files},
        )

    def test_metadata_outside_root(self):
        repository = self.get_repository(["main"], [], True)

        with patch.object(
            repository,
            "_metadata_file_allowed",
            lambda *args, **kwargs: True,  # type: ignore
        ):
            files = [
                str(f.path)
                for f in repository.get_metadata_files(
                    self.TEST_DATA / "MaliciousRepository", False, set()
                )
            ]

            self.assertFalse(any(".." in path for path in files))

    def test_source_outside_root(self):
        source_parser = SourcesParser(
            self.TEST_DATA / "MaliciousRepository/repo",
            {Path("dists/test/main/source/Sources")},
            set(),
            True,
            PackageFilter(),
        )

        files = [str(f.path) for f in source_parser.parse()]

        self.assertFalse(any(".." in path for path in files))

    def test_binary_outside_root(self):
        source_parser = PackagesParser(
            self.TEST_DATA / "MaliciousRepository/repo",
            {Path("dists/test/main/binary-amd64/Packages")},
            set(),
            True,
            PackageFilter(),
        )

        files = [str(f.path) for f in source_parser.parse()]

        self.assertFalse(any(".." in path for path in files))

    def test_signature_release(self):
        repository = self.get_repository(
            codename="bookworm",
            components=["main"],
            arches=["amd64"],
            mirror_source=True,
            mirror_path=Path("repo1"),
        )

        test_data_folder = self.TEST_DATA / "DebianBookworm"

        repository.gpg_verify = GPGVerify.OFF

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
        )

        repository.gpg_verify = GPGVerify.ON

        with self.assertRaisesRegex(
            InvalidSignatureError,
            "Unable to verify release file signature:.+/Release",
        ):
            repository.validate_release_files(
                test_data_folder,
                encode_tilde=False,
                etc_trusted=Path("/tmp/a/b/c/unknown"),
                etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
            )

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=test_data_folder / "trusted.gpg.d.asc",
        )

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=test_data_folder / "trusted.gpg.d.gpg",
        )

    def test_signature_release_unsigned(self):
        repository = self.get_repository(
            codename="bookworm",
            components=["main"],
            arches=["amd64"],
            mirror_source=True,
            mirror_path=Path("repo2"),
        )

        test_data_folder = self.TEST_DATA / "DebianBookworm"

        repository.gpg_verify = GPGVerify.OFF

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
        )

        repository.gpg_verify = GPGVerify.ON

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
        )

        repository.gpg_verify = GPGVerify.FORCE

        with self.assertRaisesRegex(
            InvalidSignatureError, "Unable to find GPG signature.+/Release"
        ):
            repository.validate_release_files(
                test_data_folder,
                encode_tilde=False,
                etc_trusted=Path("/tmp/a/b/c/unknown"),
                etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
            )

    def test_signature_inrelease(self):
        repository = self.get_repository(
            codename="bookworm",
            components=["main"],
            arches=["amd64"],
            mirror_source=True,
        )

        test_data_folder = self.TEST_DATA / "DebianBookworm"

        repository.gpg_verify = GPGVerify.OFF

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
        )

        repository.gpg_verify = GPGVerify.ON

        with self.assertRaisesRegex(
            InvalidSignatureError,
            "Unable to verify release file signature:.+/InRelease",
        ):
            repository.validate_release_files(
                test_data_folder,
                encode_tilde=False,
                etc_trusted=Path("/tmp/a/b/c/unknown"),
                etc_trusted_parts=Path("/tmp/a/b/c/unknown"),
            )

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=test_data_folder / "trusted.gpg.d.asc",
        )

        repository.validate_release_files(
            test_data_folder,
            encode_tilde=False,
            etc_trusted=Path("/tmp/a/b/c/unknown"),
            etc_trusted_parts=test_data_folder / "trusted.gpg.d.gpg",
        )


class TestSafePath(TestCase):
    def test_safepath(self):
        with TemporaryDirectory() as temp_folder:
            temp_folder = Path(temp_folder)

            root_folder = temp_folder / "a"
            b = Path("b")
            c = Path("../c")

            self.assertTrue(is_safe_path(root_folder, b))
            self.assertTrue(is_safe_path(root_folder, b / c))
            self.assertFalse(is_safe_path(root_folder, c))

    def test_symlink(self):
        with TemporaryDirectory() as temp_folder:
            temp_folder = Path(temp_folder)

            root_folder = temp_folder / "a"
            symlinked_folder = root_folder / "b"
            c = Path("c")
            d = Path("../d")

            root_folder.mkdir()
            symlinked_folder.symlink_to(root_folder)

            self.assertTrue(is_safe_path(root_folder, c))
            self.assertFalse(is_safe_path(root_folder, d))

            self.assertTrue(is_safe_path(symlinked_folder, c))
            self.assertFalse(is_safe_path(symlinked_folder, d))


class TestIndexParser(BaseTest):
    def test_packages_hashsums(self):
        parser = PackagesParser(
            self.TEST_DATA / "Indexes",
            {Path("Packages")},
            set(),
            False,
            PackageFilter(),
        )
        files = {f.path: f for f in parser.parse()}

        hashes = (
            files[Path("pool/main/n/nebula-utils/nebula-utils_1.2.0-1_amd64.deb")]
            .compression_variants[FileCompression.NONE]
            .hashes
        )
        self.assertEqual(
            hashes[HashType.MD5].hash,
            "9b2b5c3a1a9f6d7e4c8f0a2d5e7b1c3f",
        )

        self.assertEqual(
            hashes[HashType.SHA1].hash,
            "2f1c4a7b9d0e3c5a6b7c8d9e0f1a2b3c4d5e6f70",
        )

        self.assertEqual(
            hashes[HashType.SHA256].hash,
            "6d8f4a1b0c3e2f5d7a9c1b3e4d6f7a8c9b0e1d2c3a4b5c6d7e8f9a0b1c2d3e4",
        )

        self.assertEqual(
            hashes[HashType.SHA512].hash,
            "9a3f6d2c1b0e8f7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e",
        )
