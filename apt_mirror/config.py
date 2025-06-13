# SPDX-License-Identifer: GPL-3.0-or-later

import os
import subprocess
from collections.abc import Iterable, Iterator, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any, TypeVar

from apt_mirror.download import URL, Proxy
from apt_mirror.repository import (
    BaseRepository,
    ByHash,
    Codename,
    FlatDirectory,
    FlatRepository,
    GPGVerify,
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
    gpg_verify: GPGVerify
    sign_by: list[Path] | None

    @classmethod
    def from_line(cls, line: str, default_arch: str, default_gpg_verify: GPGVerify):
        log = LoggerFactory.get_logger(cls)

        repository_type, url = line.split(maxsplit=1)
        source = False
        sign_by = None

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
                    case "sign-by":
                        sign_by = list(map(Path, value.split(",")))
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

        if sign_by:
            for path in sign_by:
                if not path.is_file() or not os.access(path, os.R_OK):
                    log.warning(
                        f"The `sign-by` option contains inaccessible path: {path}"
                    )

        url = url.rstrip("/")

        return cls(
            url,
            URL.from_string(url),
            arches,
            source,
            codenames,
            components,
            by_hash,
            default_gpg_verify,
            sign_by,
        )

    def to_repository(self) -> BaseRepository:
        if self.is_flat():
            return FlatRepository(
                url=self.url,
                clean=False,
                skip_clean=set(),
                http2_disable=False,
                mirror_dist_upgrader=False,
                mirror_path=None,
                ignore_errors=set(),
                gpg_verify=self.gpg_verify,
                directories=FlatRepository.FlatDirectories(
                    (
                        directory,
                        FlatDirectory(
                            self.by_hash,
                            self.sign_by,
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
                http2_disable=False,
                mirror_dist_upgrader=False,
                mirror_path=None,
                ignore_errors=set(),
                gpg_verify=self.gpg_verify,
                codenames=Repository.Codenames(
                    (
                        codename,
                        Codename(
                            self.by_hash,
                            self.sign_by,
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
                        by_hash=self.by_hash,
                        sign_by=self.sign_by,
                        codename=codename,
                        components={
                            component: Codename.Component(
                                component, self.source, self.arches
                            )
                            for component in self.components
                        },
                    ),
                )

                if codename.by_hash == ByHash.default():
                    codename.by_hash = self.by_hash

                if not codename.sign_by:
                    codename.sign_by = self.sign_by

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
                        by_hash=self.by_hash,
                        sign_by=self.sign_by,
                        directory=directory_path,
                        mirror_source=self.source,
                        mirror_binaries=bool(self.arches),
                    ),
                )

                if directory.by_hash == ByHash.default():
                    directory.by_hash = self.by_hash

                if not directory.sign_by:
                    directory.sign_by = self.sign_by

                if not directory.mirror_binaries and bool(self.arches):
                    directory.mirror_binaries = True

                if self.source:
                    directory.mirror_source = True

    def is_flat(self):
        return any(codename.endswith("/") for codename in self.codenames)


T = TypeVar("T")


class URLDict(MutableMapping[str, T]):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__()
        self._dict: dict[str, T] = {}
        self.update(dict(*args, **kwargs))

    def _find_key(self, key: Any):
        if key in self._dict:
            return key

        if isinstance(key, str):
            if key.endswith("/"):
                stripped_key = key.rstrip("/")
                if stripped_key in self._dict:
                    return stripped_key
            else:
                key_with_slash = f"{key}/"
                if key_with_slash in self._dict:
                    return key_with_slash

        return key

    def __contains__(self, key: object) -> bool:
        return self._find_key(key) in self._dict

    def __iter__(self) -> Iterator[str]:
        return iter(self._dict)

    def __len__(self) -> int:
        return len(self._dict)

    def __getitem__(self, key: str) -> T:
        return self._dict[self._find_key(key)]

    def __setitem__(self, key: str, value: T) -> None:
        self._dict[self._find_key(key)] = value

    def __delitem__(self, key: str) -> None:
        del self._dict[self._find_key(key)]

    def copy(self):
        return URLDict(self)


class Config:
    PACKAGE_FILTERS_KEYS = {
        "include_source_name",
        "exclude_source_name",
        "include_binary_packages",
        "exclude_binary_packages",
        "include_sections",
        "exclude_sections",
        "include_tags",
        "exclude_tags",
    }

    BOOLEAN_KEYS = {
        "clean",
        "http2-disable",
        "mirror_dist_upgrader",
    }

    DATA_KEYS = {
        "ignore_errors",
        "gpg_verify",
        "mirror_path",
        "skip-clean",
    } | PACKAGE_FILTERS_KEYS

    DEFAULT_CONFIGFILE = "/etc/apt/mirror.list"
    DEFAULT_CONFIGFILE2 = "/etc/apt/mirror2.list"
    DEFAULT_BASE_PATH = "/var/spool/apt-mirror"
    DEFAULT_BASE_PATH2 = "/var/spool/apt-mirror2"

    def __init__(
        self, config_file: Path, default_base_path: str = DEFAULT_BASE_PATH
    ) -> None:
        self._log = LoggerFactory.get_logger(self)
        self._repositories: URLDict[BaseRepository] = URLDict()

        self._files = [config_file]
        config_directory = config_file.with_name(f"{config_file.name}.d")
        if config_directory.is_dir():
            for file in config_directory.glob("*"):
                if not file.is_file() or file.suffix != ".list":
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
            "nthreads": "8",
            "uvloop": "1",
            "base_path": default_base_path,
            "mirror_path": "$base_path/mirror",
            "skel_path": "$base_path/skel",
            "var_path": "$base_path/var",
            "etc_netrc": "/etc/apt/auth.conf",
            "etc_trusted": "/etc/apt/trusted.gpg",
            "etc_trusted_parts": "/etc/apt/trusted.gpg.d",
            "cleanscript": "$var_path/clean.sh",
            "gpg_verify": "off",
            "append_logs": "off",
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
        boolean_options: dict[str, set[str]] = {}
        data_options: dict[str, dict[str, list[str]]] = {}

        for file in self._files:
            with open(file, "rt", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()

                    if not line or any(
                        line.startswith(prefix) for prefix in ("#", ";")
                    ):
                        continue

                    command = next(iter(line.split(maxsplit=1)), None)

                    match line:
                        case line if command == "set":
                            _, key, value = line.split(maxsplit=2)
                            self._variables[key] = value
                        case line if line.startswith("deb"):
                            try:
                                repository_config = RepositoryConfig.from_line(
                                    line,
                                    self.default_arch,
                                    self.gpg_verify,
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
                        case line if command in self.BOOLEAN_KEYS:
                            key, repository = line.split(maxsplit=1)
                            boolean_options.setdefault(key, set()).add(repository)
                        case line if command in self.DATA_KEYS:
                            key, data = line.split(maxsplit=1)
                            data = data.split()
                            data_options.setdefault(key, {}).setdefault(
                                data[0], []
                            ).extend(data[1:])
                        case _:
                            self._log.warning(f"Unknown line in config: {line}")

        self._set_boolean_fields(boolean_options)
        self._update_mirror_paths(data_options.get("mirror_path", {}))
        self._update_ignore_errors(data_options.get("ignore_errors", {}))
        self._update_gpg_verify(data_options.get("gpg_verify", {}))
        self._update_skip_clean(data_options.get("skip-clean", {}).keys())

        self._update_filters(data_options)
        self._update_netrc()

    def _set_boolean_fields(self, options: dict[str, set[str]]):
        for option in options:
            if option not in self.BOOLEAN_KEYS:
                continue

            for url in options[option]:
                if url not in self._repositories:
                    self._log.warning(
                        f"`{option}` was specified for missing repository URL: {url}"
                    )
                    continue

                attribute = option.replace("-", "_")
                if not hasattr(self._repositories[url], attribute):
                    raise RuntimeError(
                        f"Repository object doesn't have `{attribute}` attribute"
                    )

                setattr(self._repositories[url], attribute, True)

    def _update_skip_clean(self, skip_clean: Iterable[str]):
        for key in skip_clean:
            url = URL.from_string(key)
            repositories = [
                r for r in self._repositories.values() if r.url.is_part_of(url)
            ]

            for repository in repositories:
                repository.skip_clean.add(
                    Path(url.path).relative_to(Path(repository.url.path))
                )

    def _update_mirror_paths(self, mirror_paths: dict[str, list[str]]):
        for url, paths in mirror_paths.items():
            if url not in self._repositories:
                self._log.warning(
                    f"mirror_path was specified for missing repository URL: {url}"
                )
                continue

            if not paths:
                raise RuntimeError(f"Missing mirror path for URL {url}")

            self._repositories[url].mirror_path = Path(paths[0])

    def _update_ignore_errors(self, ignore_errors: dict[str, list[str]]):
        for url, paths in ignore_errors.items():
            if url not in self._repositories:
                self._log.warning(
                    f"ignore_errors was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].ignore_errors.update(paths)

    def _update_gpg_verify(self, gpg_verify: dict[str, list[str]]):
        for url, value in gpg_verify.items():
            if url not in self._repositories:
                self._log.warning(
                    f"gpg_verify was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].gpg_verify = GPGVerify(value)

    def _update_filters(
        self,
        data_options: dict[str, dict[str, list[str]]],
    ):
        for filter_name in self.PACKAGE_FILTERS_KEYS:
            filter_data = data_options.get(filter_name, {})

            for url in filter_data:
                if url not in self._repositories:
                    self._log.warning(
                        f"{filter_name} was specified for missing repository URL: {url}"
                    )
                    continue

                getattr(self._repositories[url].package_filter, filter_name).update(
                    filter_data[url]
                )

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
        if self.append_logs:
            LoggerFactory.enable_append_logs()

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
    def repositories(self) -> URLDict[BaseRepository]:
        return self._repositories.copy()

    @property
    def gpg_verify(self) -> GPGVerify:
        return GPGVerify(self._variables["gpg_verify"])

    @property
    def append_logs(self):
        return self.get_bool("append_logs")

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
    def etc_trusted(self) -> Path:
        return self.get_path("etc_trusted")

    @property
    def etc_trusted_parts(self) -> Path:
        return self.get_path("etc_trusted_parts")

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
