# SPDX-License-Identifer: GPL-3.0-or-later

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DownloadResponse:
    _stream: Callable[[], AsyncIterator[bytes]] | None
    missing: bool = False
    error: str | None = None
    date: datetime | None = None
    size: int | None = None
    retry: bool | None = None

    def stream(self) -> AsyncIterator[bytes]:
        if not self._stream:
            raise RuntimeError("_stream property was not defined")

        return self._stream()
