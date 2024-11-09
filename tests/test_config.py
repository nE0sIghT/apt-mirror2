from pathlib import Path

from apt_mirror.apt_mirror import PathCleaner
from apt_mirror.config import Config, RepositoryConfigException
from apt_mirror.download.url import URL
from apt_mirror.netrc import NetRC
from apt_mirror.repository import ByHash
from tests.base import BaseTest


class TestConfig(BaseTest):
    def test_multiple_codenames(self):
        config = self.get_config("MixedConfig")

        self.assertEqual(len(config.repositories), 4)

        debian_security = self.ensure_repository(
            config.repositories["http://ftp.debian.org/debian-security"]
        )

        self.assertCountEqual(
            debian_security.codenames,
            ("bookworm-security", "bullseye-security", "trixie-security"),
        )

        self.assertFalse(
            debian_security.codenames["bookworm-security"].should_mirror_source()
        )
        self.assertFalse(
            debian_security.codenames["trixie-security"].should_mirror_source()
        )
        self.assertTrue(
            debian_security.codenames["bullseye-security"].should_mirror_source()
        )

        self.assertCountEqual(
            debian_security.codenames["trixie-security"].components["main"].arches,
            {
                config.default_arch,
                "amd64",
                "arm64",
                "armel",
                "armhf",
                "i386",
                "mips64el",
                "ppc64el",
                "s390x",
            },
        )

        self.assertCountEqual(
            debian_security.codenames["bullseye-security"].components["main"].arches,
            {
                config.default_arch,
                "amd64",
                "arm64",
                "armel",
                "armhf",
                "i386",
                "mips64el",
                "ppc64el",
                "s390x",
            },
        )

        self.assertCountEqual(
            debian_security.codenames["bookworm-security"].components["main"].arches,
            {config.default_arch, "arm64"},
        )

        ubuntu_security = self.ensure_repository(
            config.repositories["http://archive.ubuntu.com/ubuntu"]
        )

        self.assertCountEqual(
            ubuntu_security.codenames,
            (
                "mantic",
                "mantic-security",
                "mantic-updates",
                "mantic-backports",
                "noble",
                "noble-security",
                "noble-updates",
                "noble-backports",
            ),
        )

        flat_repository = self.ensure_flat_repository(
            config.repositories["http://mirror.something.ru/repository"]
        )

        self.assertTrue(flat_repository.is_binaries_enabled)
        self.assertEqual(
            str(flat_repository.url), "http://mirror.something.ru/repository"
        )
        self.assertCountEqual(flat_repository.directories.keys(), [Path("subpath")])
        self.assertTrue(
            flat_repository.directories[Path("subpath")].mirror_binaries, True
        )

    def test_codenames_list(self):
        config = self.get_config("MixedConfig")

        proxmox_apqa = self.ensure_repository(
            config.repositories["https://mirrors.apqa.cn/proxmox/debian/pve"]
        )

        self.assertCountEqual(
            proxmox_apqa.codenames,
            ("bookworm", "bullseye"),
        )

        self.assertCountEqual(
            proxmox_apqa.codenames["bookworm"].components["port"].arches,
            {
                config.default_arch,
                "amd64",
                "arm64",
                "i386",
            },
        )

        self.assertCountEqual(
            proxmox_apqa.codenames["bullseye"].components["port"].arches,
            {
                config.default_arch,
                "amd64",
                "arm64",
                "i386",
            },
        )

    def test_skip_clean(self):
        config = self.get_config("SkipCleanConfig")

        debian = self.ensure_repository(
            config.repositories["http://ftp.debian.org/debian"]
        )

        self.assertCountEqual(debian.skip_clean, (Path("abcd"), Path("def/def")))

        cleaner = PathCleaner(
            self.TEST_DATA / "SkipCleanConfig" / "dir1", debian.skip_clean
        )
        self.assertEqual(cleaner.clean_files_count, 0)
        self.assertEqual(cleaner.folders_count, 0)

        cleaner = PathCleaner(
            self.TEST_DATA / "SkipCleanConfig" / "dir2", debian.skip_clean
        )
        self.assertEqual(cleaner.clean_files_count, 1)
        self.assertEqual(cleaner.folders_count, 1)

    def test_by_hash(self):
        config = self.get_config("ByHashConfig")

        repository = self.ensure_repository(
            config.repositories["http://ftp.debian.org/debian-security"]
        )

        self.assertEqual(repository.codenames["trixie-security"].by_hash, ByHash.FORCE)
        self.assertEqual(repository.codenames["bookworm-security"].by_hash, ByHash.NO)
        self.assertEqual(repository.codenames["stretch-security"].by_hash, ByHash.YES)

        repository = self.ensure_repository(
            config.repositories["http://archive.ubuntu.com/ubuntu"]
        )

        self.assertEqual(repository.codenames["mantic"].by_hash, ByHash.NO)

        repository = self.ensure_repository(
            config.repositories["http://mirror.something.ru/repository"]
        )

        self.assertEqual(repository.codenames["codename"].by_hash, ByHash.NO)

    def test_dist_upgrader(self):
        config = self.get_config("MixedConfig")

        repository = self.ensure_flat_repository(
            config.repositories["http://mirror.something.ru/repository"]
        )

        self.assertFalse(repository.mirror_dist_upgrader)

        repository = self.ensure_repository(
            config.repositories["http://archive.ubuntu.com/ubuntu"]
        )

        self.assertTrue(repository.mirror_dist_upgrader)

    def test_clean(self):
        config = self.get_config("MixedConfig")

        repository = self.ensure_flat_repository(
            config.repositories["http://mirror.something.ru/repository"]
        )

        self.assertTrue(repository.clean, True)

    def test_src_arch(self):
        config = self.get_config("SrcOptionConfig")

        repository = self.ensure_repository(
            config.repositories["http://ftp.debian.org/debian-security"]
        )

        self.assertFalse(repository.is_binaries_enabled)
        self.assertTrue(repository.is_source_enabled)

        repository = self.ensure_repository(
            config.repositories["http://archive.ubuntu.com/ubuntu"]
        )

        self.assertFalse(repository.is_binaries_enabled)
        self.assertTrue(repository.is_source_enabled)

    def test_ignore_errors(self):
        config = self.get_config("IgnoreErrorsConfig")

        repository = self.ensure_repository(
            config.repositories[
                "https://packages.gitlab.com/runner/gitlab-runner/debian"
            ]
        )

        self.assertCountEqual(
            repository.ignore_errors,
            [
                "pool/bullseye/main/g/gitlab-runner/gitlab-runner_14.8.1_amd64.deb",
                "pool/bullseye/main/d",
            ],
        )

    def test_multiple_flat_directories(self):
        config = self.get_config("FlatConfig")

        repository = self.ensure_flat_repository(
            config.repositories["https://packages.ntop.org/apt-stable/20.04/"]
        )

        self.assertEqual(len(repository.directories), 3)

        self.assertTrue(repository.directories[Path("x64")].mirror_binaries)
        self.assertFalse(repository.directories[Path("x64")].mirror_source)

        self.assertFalse(repository.directories[Path("x32")].mirror_binaries)
        self.assertTrue(repository.directories[Path("x32")].mirror_source)

        self.assertTrue(repository.directories[Path("all")].mirror_binaries)
        self.assertFalse(repository.directories[Path("all")].mirror_source)

        repository = self.ensure_flat_repository(
            config.repositories["http://localhost:8080/repo"]
        )

        self.assertEqual(len(repository.directories), 2)

        self.assertTrue(repository.directories[Path("bin1/")].mirror_binaries)
        self.assertTrue(repository.directories[Path("bin1/")].mirror_source)

        self.assertTrue(repository.directories[Path("bin2/")].mirror_binaries)
        self.assertTrue(repository.directories[Path("bin2/")].mirror_source)

    def test_broken(self):
        with self.assertRaises(RepositoryConfigException):
            self.get_config("BrokenConfig")

    def test_broken_flat(self):
        with self.assertRaises(RepositoryConfigException):
            self.get_config("FlatBrokenConfig")

    def test_netrc1(self):
        netrc = NetRC(self.TEST_DATA / "NetRC" / "auth1.conf")
        self.assertEqual(
            netrc.match_machine(URL.from_string("https://host1.example.com")),
            ("user", "password"),
        )

        netrc = NetRC(self.TEST_DATA / "NetRC" / "auth4.conf")
        self.assertEqual(
            netrc.match_machine(URL.from_string("http://host1.example.com/path123")),
            ("login1", "password1"),
        )

    def test_netrc2(self):
        def ensure_auth(
            config: Config,
            repository_url: str,
            login: str | None = None,
            password: str | None = None,
        ):
            repository = self.ensure_repository(config.repositories[repository_url])
            self.assertEqual(repository.url.username, login)
            self.assertEqual(repository.url.password, password)

        etc_netrc = self.TEST_DATA / "NetRC" / "auth1.conf"
        config = self.get_modified_config("NetRC", f"set etc_netrc {etc_netrc}")

        ensure_auth(config, "http://host1.example.com/path1")
        ensure_auth(config, "https://host1.example.com/path11", "user", "password")
        ensure_auth(config, "https://host2.example.com/path2")
        ensure_auth(config, "ftp://host3.example.com/path3")

        etc_netrc = self.TEST_DATA / "NetRC" / "auth2.conf"
        config = self.get_modified_config("NetRC", f"set etc_netrc {etc_netrc}")

        ensure_auth(config, "http://host1.example.com/path1")
        ensure_auth(config, "https://host1.example.com/path11")
        ensure_auth(config, "https://host2.example.com/path2")
        ensure_auth(config, "ftp://host3.example.com/path3", "ftp", "anon")

        etc_netrc = self.TEST_DATA / "NetRC" / "auth3.conf"
        config = self.get_modified_config("NetRC", f"set etc_netrc {etc_netrc}")

        ensure_auth(config, "http://host1.example.com/path1")
        ensure_auth(config, "https://host1.example.com/path11", "some", "thing")
        ensure_auth(config, "https://host2.example.com/path2")
        ensure_auth(config, "ftp://host3.example.com/path3")

        etc_netrc = self.TEST_DATA / "NetRC" / "auth4.conf"
        config = self.get_modified_config("NetRC", f"set etc_netrc {etc_netrc}")

        ensure_auth(config, "http://host1.example.com/path1", "login1", "password1")
        ensure_auth(config, "https://host1.example.com/path11", "login2", "password2")
        ensure_auth(config, "https://host2.example.com/path2")
        ensure_auth(config, "ftp://host3.example.com/path3")

    def test_slash_independent(self):
        config = self.get_config("SlashConfig")

        repository = self.ensure_repository(
            config.repositories["http://example.com/debian1"]
        )

        self.assertTrue(repository.clean)
        self.assertTrue(repository.mirror_dist_upgrader)
        self.assertEqual(repository.mirror_path, Path("path1"))
        self.assertIn("isource1", repository.package_filter.include_source_name)
        self.assertIn("esource1", repository.package_filter.exclude_source_name)
        self.assertIn("ibinary1", repository.package_filter.include_binary_packages)
        self.assertIn("ebinary1", repository.package_filter.exclude_binary_packages)

        repository = self.ensure_repository(
            config.repositories["http://example.com/debian2/"]
        )

        self.assertTrue(repository.clean)
        self.assertTrue(repository.mirror_dist_upgrader)
        self.assertEqual(repository.mirror_path, Path("path2"))
        self.assertIn("isource2", repository.package_filter.include_source_name)
        self.assertIn("esource2", repository.package_filter.exclude_source_name)
        self.assertIn("ibinary2", repository.package_filter.include_binary_packages)
        self.assertIn("ebinary2", repository.package_filter.exclude_binary_packages)
