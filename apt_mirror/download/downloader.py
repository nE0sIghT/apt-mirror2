# SPDX-License-Identifer: GPL-3.0-or-later

import asyncio
import contextlib
import itertools
import os
import shutil
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiolimiter import AsyncLimiter

from ..aiofile import BaseAsyncIOFileWriterFactory
from ..logs import LoggerFactory
from .download_file import DownloadFile, DownloadFileCompressionVariant
from .format import format_size
from .proxy import Proxy
from .response import DownloadResponse
from .slow_rate_protector import SlowRateProtectorFactory
from .url import URL


@dataclass
class DownloaderSettings:
    url: URL
    target_root_path: Path
    aiofile_factory: BaseAsyncIOFileWriterFactory
    proxy: Proxy
    http2_disable: bool
    user_agent: str
    semaphore: asyncio.Semaphore
    slow_rate_protector_factory: SlowRateProtectorFactory
    rate_limiter: AsyncLimiter | None = None
    verify_ca_certificate: bool | str = True
    client_certificate: str | None = None
    client_private_key: str | None = None


class Downloader(ABC):
    BUFFER_SIZE = 8 * 1024 * 1024

    def __init__(self, *, settings: DownloaderSettings):
        self._log = LoggerFactory.get_logger(
            self,
            logger_id=settings.url,
        )

        self._settings = settings

        # Download queue. Reseted in download()
        self._sources: list[DownloadFile] = []
        # Downloaded files
        self._downloaded: list[DownloadFileCompressionVariant] = []
        # Umnodified files
        self._unmodified: list[DownloadFileCompressionVariant] = []
        # Either missing on server files or files with errors
        self._missing_sources: set[Path] = set()
        self._download_start = datetime.now()

        self.reset_stats()

        self.__post_init__()

    def __post_init__(self):  # noqa: B027
        pass

    def reset_stats(self):
        self._downloaded_count = 0
        self._downloaded_size = 0
        self._unmodified_count = 0
        self._unmodified_size = 0
        self._missing_count = 0
        self._missing_size = 0
        self._error_count = 0
        self._error_size = 0

    def reset_paths(self):
        self._downloaded: list[DownloadFileCompressionVariant] = []
        self._unmodified: list[DownloadFileCompressionVariant] = []
        self._missing_sources: set[Path] = set()

    def set_target_path(self, path: Path):
        self._settings.target_root_path = path

    def add(self, *args: DownloadFile):
        self._sources.extend(a for a in args)

        self.reset_stats()

    @property
    def queue_files_count(self) -> int:
        return len(self._sources)

    @property
    def queue_files_size(self) -> int:
        return sum(file.size for file in self._sources)

    @property
    def queue_files_formatted_size(self) -> str:
        return format_size(self.queue_files_size)

    @property
    def downloaded_files_count(self) -> int:
        return self._downloaded_count

    @property
    def downloaded_files_size(self) -> int:
        return self._downloaded_size

    @property
    def error_files_count(self) -> int:
        return self._error_count

    @property
    def error_files_size(self) -> int:
        return self._error_size

    @property
    def missing_files_count(self) -> int:
        return self._missing_count

    @property
    def missing_files_size(self) -> int:
        return self._missing_size

    @property
    def unmodified_files_count(self) -> int:
        return self._unmodified_count

    @property
    def unmodified_files_size(self) -> int:
        return self._unmodified_size

    async def download(self):
        async def remove_finished_tasks(tasks: set[asyncio.Task[Any]]):
            done_tasks, _ = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )

            tasks.difference_update(done_tasks)

        self._download_start = datetime.now()
        tasks: set[asyncio.Task[Any]] = set()
        progress_task = asyncio.create_task(self.progress_logger())

        while self._sources:
            source_file = self._sources.pop()

            file_unmodified = False
            if source_file.check_size:
                for variant in source_file.iter_variants():
                    target_path = (
                        self._settings.target_root_path / variant.get_source_path()
                    )

                    try:
                        stat = target_path.stat()
                        if stat.st_size == source_file.size:
                            self._unmodified_count += 1
                            self._unmodified_size += source_file.size
                            self._unmodified.append(variant)

                            file_unmodified = True
                            break
                    except FileNotFoundError:
                        pass

            if file_unmodified:
                continue

            tasks.add(asyncio.create_task(self.download_file(source_file)))

            if len(tasks) >= 128:
                await remove_finished_tasks(tasks)

        while tasks:
            await remove_finished_tasks(tasks)

        progress_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await progress_task

        self.log_status("Download finished")

    def need_update(self, path: Path, size: int | None, date: datetime | None) -> bool:
        if path.exists() and date and size:
            stat = path.stat()
            target_date = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            target_size = stat.st_size

            if date == target_date and size == target_size:
                return False

        return True

    async def progress_logger(self):
        while True:
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                return

            self.log_status("Download progress")

    def log_status(self, message: str):
        download_rate = format_size(
            self._downloaded_size
            / (datetime.now().timestamp() - self._download_start.timestamp()),
            suffix="B/sec",
        )
        self._log.info(
            message
            + f": {self._downloaded_count} ({format_size(self._downloaded_size)},"
            f" {download_rate});"
            " unmodified:"
            f" {self._unmodified_count} ({format_size(self._unmodified_size)});"
            f" missing: {self._missing_count} ({format_size(self._missing_size)});"
            f" errors: {self._error_count} ({format_size(self._error_size)})"
        )

    async def download_file(self, source_file: DownloadFile):
        async def retry(
            message: str | None = None, sleep: bool = True, skip_try: bool = False
        ):
            nonlocal tries
            if message:
                self._log.warning(message)

            if not skip_try:
                tries -= 1

            if sleep:
                await asyncio.sleep(5)

        error = False
        for variant in source_file.iter_variants():
            expected_size = variant.size

            for source_path in variant.get_all_paths():
                target_path = self._settings.target_root_path / source_path

                tries = 10
                while tries > 0:
                    async with (
                        self._settings.semaphore,
                        self.stream(source_path) as response,
                    ):
                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        if response.retry:
                            await retry(skip_try=True)
                            continue

                        if response.missing:
                            if source_file.ignore_errors or source_file.ignore_missing:
                                break

                            await retry(
                                f"File {source_path} is missing from server."
                                " Retrying..."
                            )
                            continue

                        if response.error:
                            if source_file.ignore_errors:
                                break

                            await retry(
                                f"Received error `{response.error}` while downloading"
                                f" {source_path}. Retrying..."
                            )
                            error = True
                            continue

                        if (
                            expected_size > 0
                            and response.size
                            and response.size > 0
                            and expected_size != response.size
                        ):
                            if source_file.ignore_errors:
                                break

                            await retry(
                                f"Server reported size {response.size} differs from"
                                f" expected size {expected_size} for file"
                                f" {source_path}. Retrying..."
                            )
                            error = True
                            continue

                        mirror_paths = [
                            self._settings.target_root_path / path
                            for path in variant.get_all_paths()
                        ]

                        if response.size and not self.need_update(
                            target_path, response.size, response.date
                        ):
                            self._unmodified_count += 1
                            self._unmodified_size += response.size

                            if mirror_paths:
                                self.link_or_copy(target_path, *mirror_paths)

                            self._downloaded.append(variant)
                            self._missing_sources.difference_update(
                                variant.get_all_paths()
                            )

                            return

                        size = 0
                        target_path.unlink(missing_ok=True)
                        async with self._settings.aiofile_factory.open(
                            target_path
                        ) as fp:
                            try:
                                slow_rate_protector_factory = (
                                    self._settings.slow_rate_protector_factory
                                )
                                slow_rate_protector = (
                                    slow_rate_protector_factory.for_target(
                                        variant.get_source_path()
                                    )
                                )
                                async for chunk in response.stream():
                                    if self._settings.rate_limiter:
                                        await self._settings.rate_limiter.acquire(
                                            min(
                                                len(chunk),
                                                self._settings.rate_limiter.max_rate,
                                            )
                                        )

                                    size += len(chunk)
                                    slow_rate_protector.rate(len(chunk))
                                    await fp.write(chunk)
                            except Exception as ex:  # pylint: disable=W0718
                                await retry(
                                    f"An error `{ex.__class__.__qualname__}: {ex}`"
                                    f" occured while downloading file {source_path}."
                                    " Retrying..."
                                )
                                error = True
                                continue

                        if expected_size > 0 and expected_size != size:
                            await retry(
                                f"Downloaded size {size} is differs from expected size"
                                f" {expected_size} for file {source_path}. Retrying..."
                            )
                            error = True
                            continue

                        if response.date:
                            os.utime(
                                target_path,
                                (response.date.timestamp(), response.date.timestamp()),
                            )

                        if mirror_paths:
                            self.link_or_copy(target_path, *mirror_paths)

                        self._downloaded_count += 1
                        self._downloaded_size += size

                        self._downloaded.append(variant)
                        self._missing_sources.difference_update(variant.get_all_paths())
                        return

        if source_file.ignore_errors:
            self._log.info(f"Unable to download `{source_file.path}`: ignoring")
            return

        if source_file.ignore_missing and not error:
            self._log.info(f"Optional file `{source_file.path}` is missing on server")
            return

        self._missing_sources.update(
            itertools.chain.from_iterable(
                v.get_all_paths() for v in source_file.compression_variants.values()
            )
        )

        if not error:
            self._missing_count += 1
            self._missing_size += source_file.size

            self._log.warning(
                f"Unable to download {source_file.path}: file is missing on server"
            )
            return

        self._error_count += 1
        self._error_size += source_file.size

        self._log.error(f"Unable to download {source_file.path}: no more tries")

    def get_downloaded_files(self) -> list[DownloadFileCompressionVariant]:
        return self._downloaded.copy()

    def get_unmodified_files(self) -> list[DownloadFileCompressionVariant]:
        return self._unmodified.copy()

    def get_all_files(self) -> list[DownloadFileCompressionVariant]:
        return self.get_downloaded_files() + self.get_unmodified_files()

    def get_downloaded_files_paths(self) -> set[Path]:
        return (
            set(
                itertools.chain.from_iterable(
                    v.get_all_paths() for v in self.get_all_files()
                )
            )
            - self.get_missing_sources()
        )

    def get_missing_sources(self):
        return self._missing_sources.copy()

    def has_errors(self):
        return self._error_count > 0

    def has_missing(self):
        return self._missing_count > 0

    @staticmethod
    def link_or_copy(source: Path, *targets: Path):
        if len(targets) > 1:
            Downloader.link_or_copy(source, targets[0])
            source = targets[0]

        for target in targets:
            if target == source:
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            target.unlink(missing_ok=True)

            try:
                target.hardlink_to(source)
            except OSError:
                shutil.copy2(source, target)

    @asynccontextmanager
    @abstractmethod
    async def stream(self, source_path: Path) -> AsyncGenerator[DownloadResponse, None]:
        yield  # type: ignore
