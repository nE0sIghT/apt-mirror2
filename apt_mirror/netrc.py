# SPDX-License-Identifer: GPL-3.0-or-later

import itertools
import re
from collections.abc import Generator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from .download.url import URL


class TokenType(Enum):
    MACHINE = "machine"
    LOGIN = "login"
    PASSWORD = "password"


@dataclass
class Token:
    token: TokenType
    value: str


@dataclass(frozen=True)
class Machine:
    protocol: str | None
    hostname: str | None
    port: int | None
    path: str | None

    @classmethod
    def from_string(cls, string: str):
        if "//" not in string:
            string = f"//{string}"

        url = urlparse(string)

        return cls(
            protocol=url.scheme, hostname=url.hostname, port=url.port, path=url.path
        )


class NetRCFile:
    def __init__(self, path: Path) -> None:
        self._path = path

    def tokens(self) -> Generator[Token, None, None]:
        if not self._path.is_file():
            return

        with open(self._path, "rt", encoding="utf-8") as fp:
            for line in fp:
                parts = (t for t in re.split(r"[ \t\n\r]", line) if t)
                try:
                    while True:
                        try:
                            token = TokenType(next(parts))
                        except ValueError:
                            next(parts)
                            continue

                        yield Token(token, next(parts))
                except (StopIteration, ValueError):
                    continue


class NetRC:
    def __init__(self, netrc_path: Path = Path("/etc/apt/auth.conf")) -> None:
        self._machines: dict[Machine, tuple[str, str]] = {}
        self._reset_machine()

        for file in itertools.chain(
            [netrc_path],
            netrc_path.with_name(f"{netrc_path.name}.d").glob("*.conf"),
        ):
            self._process_file(file)

    def _process_file(self, file: Path) -> None:
        for token in NetRCFile(file).tokens():
            match token.token:
                case TokenType.MACHINE:
                    self._add_machine()
                    self._machine = Machine.from_string(token.value)
                case TokenType.LOGIN:
                    self._login = token.value
                case TokenType.PASSWORD:
                    self._password = token.value

        self._add_machine()

    def _add_machine(self) -> None:
        if self._machine and self._login and self._password:
            self._machines[self._machine] = (self._login, self._password)

        self._reset_machine()

    def _reset_machine(self) -> None:
        self._machine: Machine | None = None
        self._login: str | None = None
        self._password: str | None = None

    def match_machine(self, url: URL) -> tuple[str, str] | None:
        for machine, auth in self._machines.items():
            if machine.protocol != url.scheme and (
                machine.protocol or url.scheme not in ("https", "tor+https")
            ):
                continue

            if machine.hostname != url.hostname:
                continue

            if machine.port and machine.port != url.port:
                continue

            if machine.path and not url.path.startswith(machine.path):
                continue

            return auth

        return None
