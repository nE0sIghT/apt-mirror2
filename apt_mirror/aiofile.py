# SPDX-License-Identifer: GPL-3.0-or-later

import contextlib
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Protocol

from .logs import LoggerFactory


class AsyncSupportsWrite(Protocol):
    async def write(self, data: bytes) -> int: ...


class BaseAsyncIOFileWriterFactory(ABC):
    MODE = "wb"

    def __init__(self) -> None:
        self._log = LoggerFactory.get_logger(self)

    @classmethod
    async def create(cls, *test_paths: Path) -> "BaseAsyncIOFileWriterFactory":
        clazz = cls()
        await clazz.test_storage(*test_paths)

        return clazz

    @abstractmethod
    async def test_storage(self, *test_paths: Path): ...

    @asynccontextmanager
    @abstractmethod
    async def open(self, path: Path) -> AsyncIterator[AsyncSupportsWrite]:
        yield  # type: ignore


try:
    from aiofile import async_open as aiofile_open
    from caio import (
        AsyncioContext,
        linux_aio_asyncio,
        python_aio_asyncio,
        thread_aio_asyncio,
    )

    class AsyncIOFileFactory(BaseAsyncIOFileWriterFactory):  # type: ignore
        def __init__(self) -> None:
            super().__init__()
            self._context = self._get_supported_context()

        def _get_supported_context(
            self, fallback_context: bool = False
        ) -> AsyncioContext:
            if linux_aio_asyncio and not fallback_context:
                return linux_aio_asyncio.AsyncioContext()
            elif thread_aio_asyncio:
                if not fallback_context:
                    self._log.warning(
                        "Native Linux AIO doesn't supported on this system. "
                        "Fallback to threaded AIO implementation."
                    )
                return thread_aio_asyncio.AsyncioContext()
            else:
                if not fallback_context:
                    self._log.warning(
                        "Nor native Linux AIO nor threaded AIO implementation are "
                        "supported on this system. Fallback to pure Python "
                        "implementation."
                    )
                return python_aio_asyncio.AsyncioContext()

        @asynccontextmanager
        async def _open(
            self,
            path: Path,
        ):
            yield await aiofile_open(path, mode=self.MODE, context=self._context)

        async def test_storage(self, *test_paths: Path) -> None:
            for path in test_paths:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    async with self._open(path) as fp:  # type: ignore
                        await fp.write(b" ")

                    path.unlink()
                except SystemError as e:
                    if "not supported" in str(e):
                        self._context = self._get_supported_context(
                            fallback_context=True
                        )
                        self._log.warning(
                            f"Linux AIO check failed for path {path}. Falling back to"
                            " non-AIO IO implementation."
                        )
                        break
                finally:
                    with contextlib.suppress(OSError):
                        path.unlink(missing_ok=True)

        @asynccontextmanager
        async def open(self, path: Path) -> AsyncIterator[AsyncSupportsWrite]:
            async with self._open(path) as fd:
                yield fd

except ImportError:
    from aiofiles import open as aiofiles_open
    from aiofiles.threadpool.binary import AsyncBufferedIOBase

    LoggerFactory.get_logger(__package__).warning(
        "True AIO is disabled because `aiofile` is not available, falling back to"
        " threaded wrapper via `aiofiles`. Consider using aiofile instead."
    )

    class AIOFilesWriter:
        def __init__(self, fd: AsyncBufferedIOBase) -> None:
            self._fd = fd

        async def write(self, data: bytes) -> int:
            return await self._fd.write(data)

    class AsyncIOFileFactory(BaseAsyncIOFileWriterFactory):
        @asynccontextmanager
        async def open(self, path: Path) -> AsyncIterator[AsyncSupportsWrite]:
            async with aiofiles_open(path, self.MODE) as fd:
                yield AIOFilesWriter(fd)
