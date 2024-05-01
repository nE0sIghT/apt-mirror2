# SPDX-License-Identifer: GPL-3.0-or-later

from abc import ABC, abstractmethod
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from types import TracebackType

from .logs import LoggerFactory


class BaseAsyncIOFile(ABC):
    MODE = "wb"

    def __init__(self, path: Path) -> None:
        self.path = path

    @abstractmethod
    async def write(self, data: bytes) -> int: ...


try:
    from aiofile import FileIOWrapperBase
    from aiofile import async_open as aiofile_open
except ImportError:
    from aiofiles import open as aiofiles_open

    LoggerFactory.get_logger(__package__).warning(
        "True AIO is disabled because `aiofile` is not available, falling back to"
        " threaded wrapper via `aiofiles`. Consider using aiofile instead."
    )

    class AsyncIOFile(BaseAsyncIOFile, AbstractAsyncContextManager[BaseAsyncIOFile]):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self._fd = None
            self._context = None

        async def __aenter__(self):
            self._context = aiofiles_open(self.path, mode=self.MODE)
            self._fd = await self._context.__aenter__()
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ):
            if not self._fd or not self._context:
                raise RuntimeError("Async file was not opened")

            await self._context.__aexit__(exc_type, exc_value, traceback)

        async def write(self, data: bytes) -> int:
            if not self._fd:
                raise RuntimeError("Async file was not opened")

            return await self._fd.write(data)

else:

    class AsyncIOFile(  # type: ignore
        BaseAsyncIOFile, AbstractAsyncContextManager[BaseAsyncIOFile]
    ):
        def __init__(self, path: Path) -> None:
            super().__init__(path)
            self._fd: FileIOWrapperBase | None = None
            self._context = None

        async def __aenter__(self):
            self._context = aiofile_open(self.path, self.MODE)
            self._fd = await self._context.__aenter__()
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ):
            if not self._fd or not self._context:
                raise RuntimeError("Async file was not opened")

            await self._context.__aexit__(exc_type, exc_value, traceback)

        async def write(self, data: bytes) -> int:
            if not self._fd:
                raise RuntimeError("Async file was not opened")

            return await self._fd.write(data)
