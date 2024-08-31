# SPDX-License-Identifer: GPL-3.0-or-later

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from string import Template

from apt_mirror.download import URL, Proxy
from apt_mirror.repository import (
    BaseRepository,
    ByHash,
    Codename,
    FlatDirectory,
    FlatRepository,
    Repository,
)

from .download.slow_rate_protector import SlowRateProtectorFactory
from .logs import LoggerFactory
from .netrc import NetRC
from .version import __version__


class RepositoryConfigException(Exception):
    pass


@dataclass
class RepositoryConfig:
    key: str
    url: URL
    arches: list[str]
    source: bool
    codenames: list[str]
    components: list[str]
    by_hash: ByHash

    @classmethod
    def from_line(cls, line: str, default_arch: str):
        log = LoggerFactory.get_logger(cls)

        repository_type, url = line.split(maxsplit=1)
        source = False

        arches: list[str] = []
        if "-" in repository_type:
            _, arch = repository_type.split("-", maxsplit=1)
            if arch != "src":
                arches.append(arch)
            else:
                source = True

        by_hash = ByHash.default()
        if url.startswith("["):
            options, url = url.split(sep="]", maxsplit=1)
            options = options.strip("[]").strip().split()
            for key, value in map(lambda x: x.split("=", maxsplit=1), options):
                match key:
                    case "arch":
                        for arch in value.split(","):
                            if arch == "src":
                                source = True
                                continue

                            if arch in arches:
                                continue

                            arches.append(arch)
                    case "by-hash":
                        try:
                            by_hash = ByHash(value)
                        except ValueError:
                            log.warning(
                                "Wrong `by-hash` value"
                                f" {value}. Affected config"
                                f" line: {line}"
                            )
                    case _:
                        continue

        url, codename = url.split(maxsplit=1)

        if not arches and not source:
            arches.append(default_arch)

        if " " in codename:
            codename, components = codename.split(maxsplit=1)
            components = components.split()
        else:
            components = []

        codenames = codename.split(",")

        if not all(c.endswith("/") for c in codenames) and not all(
            not c.endswith("/") for c in codenames
        ):
            raise RepositoryConfigException(
                f"Mixing flat and non-flat configuration for repository {url} is not"
                f" supported. Wrong codenames: {codenames}"
            )

        return cls(
            url, URL.from_string(url), arches, source, codenames, components, by_hash
        )

    def to_repository(self) -> BaseRepository:
        if self.is_flat():
            return FlatRepository(
                url=self.url,
                clean=False,
                skip_clean=set(),
                mirror_path=None,
                ignore_errors=set(),
                directories=FlatRepository.FlatDirectories(
                    (
                        directory,
                        FlatDirectory(
                            self.by_hash,
                            directory,
                            self.source,
                            bool(self.arches),
                        ),
                    )
                    for directory in (Path(c.rstrip("/")) for c in self.codenames)
                ),
            )
        else:
            return Repository(
                url=self.url,
                clean=False,
                skip_clean=set(),
                mirror_path=None,
                ignore_errors=set(),
                codenames=Repository.Codenames(
                    (
                        codename,
                        Codename(
                            self.by_hash,
                            codename,
                            {
                                component: Codename.Component(
                                    component, self.source, self.arches
                                )
                                for component in self.components
                            },
                        ),
                    )
                    for codename in self.codenames
                ),
            )

    def update_repository(self, repository: BaseRepository):
        if isinstance(repository, FlatRepository) != self.is_flat():
            raise RepositoryConfigException(
                "Mixing of flat and non flat repositories is not supported for url"
                f" {self.url}"
            )

        for codename in self.codenames:
            if isinstance(repository, Repository):
                codename = repository.codenames.setdefault(
                    codename,
                    Codename(
                        self.by_hash,
                        codename,
                        {
                            component: Codename.Component(
                                component, self.source, self.arches
                            )
                            for component in self.components
                        },
                    ),
                )

                if codename.by_hash == ByHash.default():
                    codename.by_hash = self.by_hash

                for component in self.components:
                    component = codename.components.setdefault(
                        component,
                        Codename.Component(component, self.source, self.arches),
                    )

                    for arch in self.arches:
                        if arch not in component.arches:
                            component.arches.append(arch)

                    if self.source:
                        component.mirror_source = True

            elif isinstance(repository, FlatRepository):
                directory_path = Path(codename.rstrip("/"))
                directory = repository.directories.setdefault(
                    directory_path,
                    FlatDirectory(
                        self.by_hash, directory_path, self.source, bool(self.arches)
                    ),
                )

                if directory.by_hash == ByHash.default():
                    directory.by_hash = self.by_hash

                if not directory.mirror_binaries and bool(self.arches):
                    directory.mirror_binaries = True

                if self.source:
                    directory.mirror_source = True

    def is_flat(self):
        return any(codename.endswith("/") for codename in self.codenames)


class Config:
    @dataclass
    class PackageFilter:
        include_source_name: dict[str, set[str]] = field(default_factory=dict)
        exclude_source_name: dict[str, set[str]] = field(default_factory=dict)
        include_binary_packages: dict[str, set[str]] = field(default_factory=dict)
        exclude_binary_packages: dict[str, set[str]] = field(default_factory=dict)

    DEFAULT_CONFIGFILE = "/etc/apt/mirror.list"

    def __init__(self, config_file: Path) -> None:
        self._log = LoggerFactory.get_logger(self)
        self._repositories: dict[str, BaseRepository] = {}

        self._files = [config_file]
        config_directory = config_file.with_name(f"{config_file.name}.d")
        if config_directory.is_dir():
            for file in config_directory.glob("*"):
                if not file.is_file() or not file.suffix == ".list":
                    continue

                self._files.append(file)

        try:
            default_arch = subprocess.run(
                ["dpkg", "--print-architecture"],
                stdout=subprocess.PIPE,
                check=False,
                encoding="utf-8",
            ).stdout.strip()

            if not default_arch:
                raise FileNotFoundError()
        except FileNotFoundError:
            default_arch = "amd64"

        self._variables: dict[str, str] = {
            "defaultarch": default_arch,
            "nthreads": "20",
            "uvloop": "1",
            "base_path": "/var/spool/apt-mirror",
            "mirror_path": "$base_path/mirror",
            "skel_path": "$base_path/skel",
            "var_path": "$base_path/var",
            "etc_netrc": "/etc/apt/auth.conf",
            "cleanscript": "$var_path/clean.sh",
            "write_file_lists": "off",
            "run_postmirror": "0",
            "postmirror_script": "$var_path/postmirror.sh",
            "_contents": "1",
            "_autoclean": "0",
            "wipe_size_ratio": "0.4",
            "wipe_count_ratio": "0.4",
            "_tilde": "0",
            "limit_rate": "100m",
            "slow_rate_protection": "on",
            "slow_rate_startup": "15",
            "slow_rate": "100k",
            "unlink": "0",
            "use_proxy": "off",
            "http_proxy": "",
            "https_proxy": "",
            "proxy_user": "",
            "proxy_password": "",
            "http_user_agent": f"apt-mirror2/{__version__}",
            "no_check_certificate": "0",
            "certificate": "",
            "private_key": "",
            "ca_certificate": "",
            "prometheus_enable": "off",
            "prometheus_host": "localhost",
            "prometheus_port": "8000",
            "release_files_retries": "15",
        }

        self._parse_config_file()
        self._substitute_variables()

    def _parse_config_file(self):
        clean: list[str] = []
        skip_clean: list[str] = []
        mirror_paths: dict[str, Path] = {}
        ignore_errors: dict[str, set[str]] = {}
        package_filter = Config.PackageFilter()

        for file in self._files:
            with open(file, "rt", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()

                    match line:
                        case line if line.startswith("set "):
                            _, key, value = line.split(maxsplit=2)
                            self._variables[key] = value
                        case line if line.startswith("deb"):
                            try:
                                repository_config = RepositoryConfig.from_line(
                                    line, self.default_arch
                                )
                            except ValueError:
                                self._log.warning(
                                    f"Unable to parse repository config line: {line}"
                                )
                                continue

                            repository = self._repositories.get(repository_config.key)
                            if repository:
                                repository_config.update_repository(repository)
                            else:
                                self._repositories[repository_config.key] = (
                                    repository_config.to_repository()
                                )
                        case line if line.startswith("clean "):
                            _, url = line.split()
                            clean.append(url)
                        case line if line.startswith("skip-clean "):
                            _, url = line.split()
                            skip_clean.append(url)
                        case line if line.startswith("mirror_path "):
                            _, url, path = line.split(maxsplit=2)
                            mirror_paths[url] = Path(path.strip("/"))
                        case line if line.startswith("ignore_errors "):
                            _, url, path = line.split(maxsplit=2)
                            ignore_errors.setdefault(url, set()).add(path)
                        case line if line.startswith("include_source_name "):
                            sources = line.split()[1:]
                            url = sources.pop(0)

                            package_filter.include_source_name.setdefault(
                                url, set()
                            ).update(sources)
                        case line if line.startswith("exclude_source_name "):
                            sources = line.split()[1:]
                            url = sources.pop(0)

                            package_filter.exclude_source_name.setdefault(
                                url, set()
                            ).update(sources)
                        case line if line.startswith("include_binary_packages "):
                            packages = line.split()[1:]
                            url = packages.pop(0)

                            package_filter.include_binary_packages.setdefault(
                                url, set()
                            ).update(packages)
                        case line if line.startswith("exclude_binary_packages "):
                            packages = line.split()[1:]
                            url = packages.pop(0)

                            package_filter.exclude_binary_packages.setdefault(
                                url, set()
                            ).update(packages)
                        case line if not line or any(
                            line.startswith(prefix) for prefix in ("#", ";")
                        ):
                            pass
                        case _:
                            self._log.warning(f"Unknown line in config: {line}")

        self._update_clean(clean)
        self._update_skip_clean(skip_clean)
        self._update_mirror_paths(mirror_paths)
        self._update_ignore_errors(ignore_errors)
        self._update_filters(package_filter)
        self._update_netrc()

    def _update_clean(self, clean: list[str]):
        for url in clean:
            if url not in self._repositories:
                self._log.warning(
                    f"Clean was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].clean = True

    def _update_skip_clean(self, skip_clean: list[str]):
        for key in skip_clean:
            url = URL.from_string(key)
            repositories = [
                r for r in self._repositories.values() if r.url.is_part_of(url)
            ]

            for repository in repositories:
                repository.skip_clean.add(
                    Path(url.path).relative_to(Path(repository.url.path))
                )

    def _update_mirror_paths(self, mirror_paths: dict[str, Path]):
        for url, path in mirror_paths.items():
            if url not in self._repositories:
                self._log.warning(
                    f"mirror_path was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].mirror_path = path

    def _update_ignore_errors(self, ignore_errors: dict[str, set[str]]):
        for url, paths in ignore_errors.items():
            if url not in self._repositories:
                self._log.warning(
                    f"ignore_errors was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].ignore_errors.update(paths)

    def _update_filters(
        self,
        package_filter: "Config.PackageFilter",
    ):
        for url, repository in self._repositories.items():
            repository.package_filter.include_source_name.update(
                package_filter.include_source_name.get(url, set())
            )
            repository.package_filter.exclude_source_name.update(
                package_filter.exclude_source_name.get(url, set())
            )
            repository.package_filter.include_binary_packages.update(
                package_filter.include_binary_packages.get(url, set())
            )
            repository.package_filter.exclude_binary_packages.update(
                package_filter.exclude_binary_packages.get(url, set())
            )

        for filter_name in (
            "include_source_name",
            "exclude_source_name",
            "include_binary_packages",
            "exclude_binary_packages",
        ):
            for url in getattr(package_filter, filter_name):
                if url not in self._repositories:
                    self._log.warning(
                        f"{filter_name} was specified for missing repository URL: {url}"
                    )
                    continue

    def _update_netrc(self):
        netrc = NetRC(self.etc_netrc)

        for repository in self._repositories.values():
            url = repository.url
            auth = netrc.match_machine(url)

            if auth and not url.username and not url.password:
                url.username, url.password = auth

    def _substitute_variables(self):
        max_tries = 16
        template_found = False
        while max_tries == 16 or template_found:
            template_found = False
            for key, value in self._variables.items():
                if "$" not in value:
                    continue

                self._variables[key] = Template(value).substitute(self._variables)
                template_found = True

            max_tries -= 1
            if max_tries < 1:
                raise ValueError(
                    "apt-mirror: too many substitutions while evaluating variables"
                )

    def __getitem__(self, key: str) -> str:
        if key not in self._variables:
            raise KeyError(
                f"Variable {key} is not defined in the config file {self._files[0]}"
            )

        return self._variables[key]

    def create_working_directories(self):
        for variable in ("mirror_path", "base_path", "var_path"):
            path = Path(self[variable])
            path.mkdir(parents=True, exist_ok=True)

    def init_log_files(self):
        LoggerFactory.add_log_file(None, self.var_path / "apt-mirror2.log")
        for repository in self.repositories.values():
            log_name = repository.as_filename(self.encode_tilde)
            self._add_url_log_file(repository.url, self.var_path / f"{log_name}.log")

    def _add_url_log_file(self, repository_url: URL, log_file: Path):
        LoggerFactory.add_log_file(repository_url, log_file)

    def get_bool(self, key: str) -> bool:
        return bool(self[key]) and self[key].lower() not in ("0", "off", "no")

    def get_path(self, key: str) -> Path:
        return Path(self[key])

    def get_size(self, key: str) -> int:
        suffix = self[key][-1:]

        if not suffix.isnumeric():
            value = int(self[key][:-1])
            match suffix.lower():
                case "k":
                    return value * 1024
                case "m":
                    return value * 1024 * 1024
                case _:
                    raise ValueError(
                        f"Wrong `{key}` configuration suffix: {self[key]}. Allowed"
                        " suffixes: k, m"
                    )

        return int(self[key])

    def as_environment(self) -> dict[str, str]:
        return {f"APT_MIRROR_{k.upper()}": v for k, v in self._variables.items()}

    @property
    def autoclean(self) -> bool:
        return self.get_bool("_autoclean")

    @property
    def wipe_size_ratio(self) -> float:
        return float(self._variables["wipe_size_ratio"])

    @property
    def wipe_count_ratio(self) -> float:
        return float(self._variables["wipe_count_ratio"])

    @property
    def base_path(self) -> Path:
        return self.get_path("base_path")

    @property
    def verify_ca_certificate(self) -> bool | str:
        if self.get_bool("no_check_certificate"):
            return False

        if self._variables.get("ca_certificate"):
            return self["ca_certificate"]

        return True

    @property
    def client_private_key(self) -> str:
        return self["private_key"]

    @property
    def client_certificate(self) -> str:
        return self["certificate"]

    @property
    def cleanscript(self) -> Path:
        return self.get_path("cleanscript")

    @property
    def default_arch(self):
        return self["defaultarch"]

    @property
    def encode_tilde(self):
        return self.get_bool("_tilde")

    @property
    def limit_rate(self) -> int:
        return self.get_size("limit_rate")

    @property
    def slow_rate_protector_factory(self) -> SlowRateProtectorFactory:
        return SlowRateProtectorFactory(
            self.slow_rate_protection,
            self.slow_rate_startup,
            self.slow_rate,
        )

    @property
    def slow_rate_protection(self) -> bool:
        return self.get_bool("slow_rate_protection")

    @property
    def slow_rate_startup(self) -> int:
        return int(self._variables["slow_rate_startup"])

    @property
    def slow_rate(self) -> int:
        return self.get_size("slow_rate")

    @property
    def nthreads(self) -> int:
        return int(self._variables["nthreads"])

    @property
    def mirror_path(self) -> Path:
        return self.get_path("mirror_path")

    @property
    def postmirror_script(self) -> Path:
        return self.get_path("postmirror_script")

    @property
    def repositories(self):
        return self._repositories.copy()

    @property
    def write_file_lists(self):
        return self.get_bool("write_file_lists")

    @property
    def run_postmirror(self):
        return self.get_bool("run_postmirror")

    @property
    def skel_path(self) -> Path:
        return self.get_path("skel_path")

    @property
    def use_uvloop(self) -> bool:
        return self.get_bool("uvloop")

    @property
    def var_path(self) -> Path:
        return self.get_path("var_path")

    @property
    def etc_netrc(self) -> Path:
        return self.get_path("etc_netrc")

    @property
    def proxy(self) -> Proxy:
        return Proxy(
            use_proxy=self.get_bool("use_proxy"),
            http_proxy=self["http_proxy"],
            https_proxy=self["https_proxy"],
            username=self._variables.get("proxy_user"),
            password=self._variables.get("proxy_password"),
        )

    @property
    def user_agent(self) -> str:
        return self["http_user_agent"]

    @property
    def prometheus_enable(self) -> bool:
        return self.get_bool("prometheus_enable")

    @property
    def prometheus_host(self) -> str:
        return self["prometheus_host"]

    @property
    def prometheus_port(self) -> int:
        return int(self["prometheus_port"])

    @property
    def release_files_retries(self) -> int:
        return max(1, int(self["release_files_retries"]))
