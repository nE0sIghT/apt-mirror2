# SPDX-License-Identifer: GPL-3.0-or-later

import subprocess
from pathlib import Path
from string import Template

from apt_mirror.download import URL, Proxy
from apt_mirror.repository import BaseRepository, FlatRepository, Repository

from .logs import get_logger


class Config:
    DEFAULT_CONFIGFILE = "/etc/apt/mirror.list"

    def __init__(self, config_file: Path) -> None:
        self._log = get_logger(self)
        self._repositories: dict[URL, BaseRepository] = {}

        self._files = [config_file]
        config_directory = config_file.with_name(f"{config_file.name}.d")
        if config_directory.is_dir():
            for file in config_directory.glob("*"):
                if not file.is_file() or not file.suffix == ".list":
                    continue

                self._files.append(file)

        try:
            default_arch = subprocess.check_output(
                ["dpkg", "--print-architecture"], encoding="utf-8"
            )
        except subprocess.CalledProcessError:
            default_arch = "amd64"

        self._variables: dict[str, str] = {
            "defaultarch": default_arch,
            "nthreads": "20",
            "uvloop": "1",
            "base_path": "/var/spool/apt-mirror",
            "mirror_path": "$base_path/mirror",
            "skel_path": "$base_path/skel",
            "var_path": "$base_path/var",
            "cleanscript": "$var_path/clean.sh",
            "run_postmirror": "0",
            "postmirror_script": "$var_path/postmirror.sh",
            "_contents": "1",
            "_autoclean": "0",
            "_tilde": "0",
            "limit_rate": "100m",
            "unlink": "0",
            "use_proxy": "off",
            "http_proxy": "",
            "https_proxy": "",
            "proxy_user": "",
            "proxy_password": "",
            "no_check_certificate": "0",
            "certificate": "",
            "private_key": "",
            "ca_certificate": "",
        }

        self._parse_config_file()
        self._substitute_variables()

    def _parse_config_file(self):
        clean: list[URL] = []
        mirror_paths: dict[URL, Path] = {}

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
                                repository_type, url = line.split(maxsplit=1)
                                source = False

                                arches: list[str] = []
                                if "-" in repository_type:
                                    _, arch = repository_type.split("-", maxsplit=1)
                                    if arch != "src":
                                        arches.append(arch)
                                    else:
                                        source = True

                                if url.startswith("["):
                                    options, url = url.split(sep="]", maxsplit=1)
                                    options = options.strip("[]").strip().split()
                                    for key, value in map(
                                        lambda x: x.split("=", maxsplit=1), options
                                    ):
                                        if key != "arch":
                                            continue

                                        for arch in value.split(","):
                                            if arch in arches:
                                                continue

                                            arches.append(arch)

                                url, codename = url.split(maxsplit=1)
                                url = URL.from_string(url)

                                if not arches and not line.startswith("deb-src"):
                                    arches.append(self.default_arch)

                                repository = self._repositories.get(url)
                                if repository:
                                    repository.arches += [
                                        arch
                                        for arch in arches
                                        if arch not in repository.arches
                                    ]

                                    if source:
                                        repository.source = source
                                else:
                                    if codename.endswith("/"):
                                        self._repositories[url] = FlatRepository(
                                            url=url,
                                            source=source,
                                            arches=arches,
                                            clean=False,
                                            mirror_path=None,
                                            directory=codename,
                                        )
                                    else:
                                        codename, components = codename.split(
                                            maxsplit=1
                                        )
                                        components = components.split()

                                        self._repositories[url] = Repository(
                                            url=url,
                                            source=source,
                                            arches=arches,
                                            clean=False,
                                            mirror_path=None,
                                            codename=codename,
                                            components=components,
                                        )

                            except ValueError:
                                self._log.warning(
                                    f"Unable to parse repository config line: {line}"
                                )
                        case line if line.startswith("clean "):
                            _, url = line.split()
                            clean.append(URL.from_string(url))
                        case line if line.startswith("mirror_path "):
                            _, url, path = line.split(maxsplit=2)
                            mirror_paths[URL.from_string(url)] = Path(path.strip("/"))
                        case line if not line or any(
                            line.startswith(prefix) for prefix in ("#", ";")
                        ):
                            pass
                        case _:
                            self._log.warning(f"Unknown line in config: {line}")

        self._update_clean(clean)
        self._update_mirror_paths(mirror_paths)

    def _update_clean(self, clean: list[URL]):
        for url in clean:
            if url not in self._repositories:
                self._log.warning(
                    f"Clean was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].clean = True

    def _update_mirror_paths(self, mirror_paths: dict[URL, Path]):
        for url, path in mirror_paths.items():
            if url not in self._repositories:
                self._log.warning(
                    f"mirror_path was specified for missing repository URL: {url}"
                )
                continue

            self._repositories[url].mirror_path = path

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

    def get_bool(self, key: str) -> bool:
        return bool(self[key]) and self[key].lower() not in ("0", "off", "no")

    def get_path(self, key: str) -> Path:
        return Path(self[key])

    @property
    def autoclean(self) -> bool:
        return self.get_bool("_autoclean")

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
    def limit_rate(self) -> int | None:
        if "limit_rate" not in self._variables:
            return None

        suffix = self["limit_rate"][-1:]

        if not suffix.isnumeric():
            limit_rate = int(self["limit_rate"][:-1])
            match suffix.lower():
                case "k":
                    return limit_rate * 1024
                case "m":
                    return limit_rate * 1024 * 1024
                case _:
                    raise ValueError(
                        f"Wrong limit_rate configuration suffix: {self['limit_rate']}"
                    )

        return int(self["limit_rate"])

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
    def proxy(self) -> Proxy:
        return Proxy(
            use_proxy=self.get_bool("use_proxy"),
            http_proxy=self["http_proxy"],
            https_proxy=self["https_proxy"],
            username=self._variables.get("proxy_user"),
            password=self._variables.get("proxy_password"),
        )
