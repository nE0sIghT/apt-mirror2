# SPDX-License-Identifer: GPL-3.0-or-later

from dataclasses import dataclass
from pathlib import Path
from urllib import parse


@dataclass
class URL:
    scheme: str
    netloc: str
    path: str
    params: str
    query: str
    fragment: str
    hostname: str | None
    port: int | None
    username: str | None
    password: str | None

    @classmethod
    def from_string(cls, url_string: str):
        url = parse.urlparse(url_string)
        return cls(
            scheme=url.scheme,
            netloc=url.netloc,
            path=url.path,
            params=url.params,
            query=url.query,
            fragment=url.fragment,
            hostname=url.hostname,
            port=url.port,
            username=url.username,
            password=url.password,
        )

    def get_host(self):
        _, _, host = self.netloc.rpartition("@")
        return host

    def without_auth(self):
        return parse.urlunparse(
            (
                self.scheme,
                self.get_host(),
                self.path,
                self.params,
                self.query,
                self.fragment,
            )
        )

    def as_filesystem_path(self, encode_tilde: bool) -> Path:
        path = Path(self.get_host()) / self.path.lstrip("/")

        if encode_tilde:
            return Path(str(path).replace("~", "%7E"))

        return path

    def for_path(self, path: Path | str) -> str:
        str_path = str(path)

        base_path = self.path
        if base_path.endswith("/"):
            base_path = base_path[:-1]

        if str_path.startswith("/"):
            str_path = str_path[1:]

        return parse.urlunparse(
            (
                self.scheme,
                self.get_host(),
                f"{base_path}/{str_path}",
                self.params,
                self.query,
                self.fragment,
            )
        )

    def is_part_of(self, url: "URL"):
        return str(url).startswith(str(self))

    def __str__(self) -> str:
        return self.without_auth()

    def __hash__(self) -> int:
        return hash(self.without_auth())

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, URL):
            return False

        return self.without_auth() == __value.without_auth()
