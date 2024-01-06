# SPDX-License-Identifer: GPL-3.0-or-later

import asyncio
import itertools
import os
import shutil
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterator, Callable, Sequence
from urllib import parse

import aioftp  # type: ignore
import httpx
from aiofile import async_open
from aioftp.client import DataConnectionThrottleStreamIO  # type: ignore
from aioftp.errors import StatusCodeError  # type: ignore

from .logs import get_logger


class UnsupportedURLException(ValueError):
    pass


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

    def for_path(self, path: str) -> str:
        base_path = self.path
        if base_path.endswith("/"):
            base_path = base_path[:-1]

        if path.startswith("/"):
            path = path[1:]

        return parse.urlunparse(
            (
                self.scheme,
                self.get_host(),
                f"{base_path}/{path}",
                self.params,
                self.query,
                self.fragment,
            )
        )

    def __str__(self) -> str:
        return self.without_auth()

    def __hash__(self) -> int:
        return hash(self.without_auth())

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, URL):
            return False

        return self.without_auth() == __value.without_auth()


class HashType(Enum):
    SHA512 = "SHA512"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5Sum"


@dataclass
class HashSum:
    type: HashType
    hash: str


@dataclass
class DownloadFile:
    path: Path
    size: int
    hashes: dict[HashType, HashSum]
    use_by_hash: bool
    check_size: bool = False

    @classmethod
    def from_path(cls, path: Path):
        return cls(path=path, size=0, hashes={}, use_by_hash=False)

    def get_source_path(self) -> Path:
        if self.use_by_hash:
            for hash_type in HashType:
                if hash_type in self.hashes:
                    return (
                        self.path.parent
                        / "by-hash"
                        / hash_type.value
                        / self.hashes[hash_type].hash
                    )

        return self.path

    def get_all_paths(self) -> Sequence[Path]:
        paths: list[Path] = []

        if self.use_by_hash:
            paths += [
                self.path.parent / "by-hash" / hashsum.type.value / hashsum.hash
                for hashsum in self.hashes.values()
            ]

        return paths + [self.path]

    def __hash__(self) -> int:
        return hash(self.path)

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f"DownloadFile: path: {self.path}, size: {self.size}"


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


class Downloader(ABC):
    BUFFER_SIZE = 8 * 1024 * 1024

    @staticmethod
    async def for_url(
        url: URL, target_path: Path, semaphore: asyncio.Semaphore
    ) -> "Downloader":
        if url.scheme.startswith("http"):
            return HTTPDownloader(url, target_path, semaphore)
        elif url.scheme.startswith("ftp"):
            return FTPDownloader(url, target_path, semaphore)

        raise UnsupportedURLException(f"Unsupported URL scheme: {url.scheme}")

    def __init__(self, url: URL, target_root_path: Path, semaphore: asyncio.Semaphore):
        self._log = get_logger(self)

        self._url = url
        self._target_root_path = target_root_path
        self._semaphore = semaphore

        # Download queue. Reseted in download()
        self._sources: list[DownloadFile] = []
        # All paths ever added to this instance
        self._all_sources: set[Path] = set()
        # Either missing on server files or files with errors
        self._missing_sources: set[Path] = set()
        self._download_start = datetime.now()

        self.reset_stats()

    def reset_stats(self):
        self._downloaded_count = 0
        self._downloaded_size = 0
        self._actual_count = 0
        self._actual_size = 0
        self._missing_count = 0
        self._missing_size = 0
        self._error_count = 0
        self._error_size = 0

    def set_target_path(self, path: Path):
        self._target_root_path = path

    def add(self, *args: DownloadFile):
        self._sources.extend(a for a in args)
        self._all_sources.update(path for a in args for path in a.get_all_paths())

        self.reset_stats()

    @property
    def queue_files_count(self):
        return len(self._sources)

    @property
    def queue_files_size(self):
        return self.format_size(sum(file.size for file in self._sources))

    # Fred Cirera
    # https://stackoverflow.com/a/1094933
    @staticmethod
    def format_size(size: float, suffix: str = "B"):
        for unit in ("", "Ki", "Mi", "Gi"):
            if abs(size) < 1024.0:
                return f"{size:3.1f} {unit}{suffix}"

            size /= 1024.0

        return f"{size:.1f} Ti{suffix}"

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
            target_path = self._target_root_path / source_file.get_source_path()
            mirror_paths = [
                self._target_root_path / path for path in source_file.get_all_paths()
            ]

            if source_file.check_size:
                try:
                    stat = target_path.stat()
                    if stat.st_size == source_file.size:
                        self._actual_count += 1
                        self._actual_size += source_file.size
                        continue
                except FileNotFoundError:
                    pass

            tasks.add(
                asyncio.create_task(
                    self.download_path(
                        source_file.path,
                        target_path,
                        expected_size=source_file.size,
                        mirror_paths=mirror_paths,
                    )
                )
            )

            if len(tasks) >= 128:  # pylint: disable=W0212
                await remove_finished_tasks(tasks)

        while tasks:
            await remove_finished_tasks(tasks)

        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass

        self.log_status("Download finished")

    async def progress_logger(self):
        while True:
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                return

            self.log_status("Download progress")

    def log_status(self, message: str):
        download_rate = self.format_size(
            self._downloaded_size
            / (datetime.now().timestamp() - self._download_start.timestamp()),
            suffix="B/sec",
        )
        self._log.info(
            message
            + f": {self._downloaded_count} ({self.format_size(self._downloaded_size)},"
            f" {download_rate});"
            " not changed:"
            f" {self._actual_count} ({self.format_size(self._actual_size)});"
            f" missing: {self._missing_count} ({self.format_size(self._missing_size)});"
            f" errors: {self._error_count} ({self.format_size(self._error_size)})"
        )

    async def download_path(
        self,
        source_path: Path,
        target_path: Path,
        expected_size: int,
        mirror_paths: Sequence[Path],
    ):
        async def retry(
            message: str | None = None, sleep: bool = True, skip_try: bool = False
        ):
            nonlocal tries
            if message:
                self._log.warning(message)

            if skip_try:
                tries -= 1

            if sleep:
                await asyncio.sleep(5)

        tries = 15
        while tries > 0:
            async with (
                self.stream(source_path) as response,
                self._semaphore,
            ):
                target_path.parent.mkdir(parents=True, exist_ok=True)

                if response.retry:
                    await retry(skip_try=True)
                    continue

                if response.missing:
                    self._missing_count += 1
                    self._missing_size += expected_size
                    self._missing_sources.update(
                        itertools.chain([source_path], mirror_paths)
                    )

                    return

                if response.error:
                    await retry(
                        f"Received error `{response.error}` while downloading"
                        f" {source_path}. Retrying..."
                    )
                    continue
                if (
                    expected_size > 0
                    and response.size
                    and response.size > 0
                    and expected_size != response.size
                ):
                    await retry(
                        f"Server reported size {response.size} is differs from"
                        f" expected size {expected_size} for file {source_path}."
                        " Retrying..."
                    )
                    continue

                if target_path.exists():
                    if response.date and response.size:
                        target_stat = target_path.stat()
                        target_date = datetime.fromtimestamp(
                            target_stat.st_mtime, tz=timezone.utc
                        )
                        target_size = target_stat.st_size

                        if (
                            response.date == target_date
                            and response.size == target_size
                        ):
                            self._actual_count += 1
                            self._actual_size += target_size
                            return

                size = 0
                async with async_open(target_path, "wb") as fp:
                    try:
                        async for chunk in response.stream():
                            size += len(chunk)
                            await fp.write(chunk)
                    except Exception as ex:  # pylint: disable=W0718
                        await retry(
                            f"An error `{ex.__class__.__qualname__}: {ex}` occured"
                            f" while downloading file {source_path}. Retrying..."
                        )
                        continue

                if expected_size > 0 and expected_size != size:
                    await retry(
                        f"Downloaded size {size} is differs from expected size"
                        f" {expected_size} for file {source_path}. Retrying..."
                    )
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
                return

        self._error_count += 1
        self._error_size += expected_size
        self._missing_sources.update(itertools.chain([source_path], mirror_paths))

        self._log.error(f"Unable to download {source_path}: no more tryes")

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


class HTTPDownloader(Downloader):
    def __init__(self, url: URL, target_root_path: Path, semaphore: asyncio.Semaphore):
        super().__init__(url, target_root_path, semaphore)

        auth = None
        if url.username and url.password:
            auth = (url.username, url.password)

        base_url = str(url)
        if not base_url.endswith("/"):
            base_url += "/"

        self._httpx = httpx.AsyncClient(
            base_url=base_url,
            auth=auth,
            timeout=None,
            follow_redirects=True,
            transport=httpx.AsyncHTTPTransport(
                verify=True,
                http1=True,
                http2=True,
                limits=httpx.Limits(
                    max_connections=256,
                    max_keepalive_connections=32,
                    keepalive_expiry=5,
                ),
                retries=5,
            ),
            max_redirects=5,
            headers={
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            },
        )

    def aiter_bytes(self, response: httpx.Response):
        def func():
            return response.aiter_bytes(chunk_size=self.BUFFER_SIZE)

        return func

    @asynccontextmanager
    async def stream(self, source_path: Path):
        try:
            async with (self._httpx.stream("GET", str(source_path)) as response,):
                date: datetime | None
                try:
                    date = parsedate_to_datetime(  # type: ignore
                        response.headers.get("Last-Modified")
                    )
                except ValueError:
                    date = None

                try:
                    size = int(response.headers.get("Content-Length"))
                except ValueError:
                    size = None

                yield DownloadResponse(
                    missing=response.is_client_error,
                    error=(
                        f"HTTP/{response.status_code}"
                        if response.is_server_error
                        else None
                    ),
                    date=date,  # type: ignore
                    size=size,
                    _stream=self.aiter_bytes(response),
                )
        except httpx.RemoteProtocolError as ex:
            # https://github.com/encode/httpx/discussions/2056
            server_disconnected = (
                bool(ex.args) and "Server disconnected" not in ex.args[0]
            )

            yield DownloadResponse(
                _stream=None,
                retry=server_disconnected,
                error=str(ex) if not server_disconnected else None,
            )
        except Exception as ex:  # pylint: disable=W0718
            yield DownloadResponse(
                _stream=None,
                error=f"{ex.__class__.__qualname__}: {str(ex)}",
            )


class FTPFileMissingException(Exception):
    pass


class FTPDownloader(Downloader):
    def iter_by_block(self, stream: aioftp.DataConnectionThrottleStreamIO):
        def func() -> AsyncIterator[bytes]:
            return stream.iter_by_block(chunk_size=self.BUFFER_SIZE)  # type: ignore

        return func

    @asynccontextmanager
    async def stream(self, source_path: Path):
        stream: DataConnectionThrottleStreamIO

        try:
            async with aioftp.Client.context(  # type: ignore
                self._url.hostname,
                port=self._url.port or aioftp.DEFAULT_PORT,
                user=self._url.username or aioftp.DEFAULT_USER,
                password=self._url.password or aioftp.DEFAULT_PASSWORD,
            ) as ftp:
                with aioftp.setlocale("C"):  # type: ignore
                    date = None
                    size = None
                    try:
                        stat: dict[str, str] = await ftp.stat(  # type: ignore
                            source_path
                        )

                        if stat.get("type") != "file":  # type: ignore
                            raise FTPFileMissingException()

                        try:
                            size = int(stat["size"])  # type: ignore
                            date = datetime.fromtimestamp(
                                int(stat["modify"]),  # type: ignore
                                tz=timezone.utc,
                            )
                        except (KeyError, ValueError):
                            pass
                    except (StatusCodeError, FTPFileMissingException) as ex:
                        if (
                            isinstance(ex, FTPFileMissingException)
                            or ex.received_codes[-1] != "550"
                        ):
                            yield DownloadResponse(_stream=None, missing=True)
                        else:
                            yield DownloadResponse(_stream=None, error=str(ex))

                stream: aioftp.DataConnectionThrottleStreamIO
                async with ftp.download_stream(source_path) as stream:  # type: ignore
                    yield DownloadResponse(
                        missing=False,
                        error=None,
                        date=date,
                        size=size,
                        _stream=self.iter_by_block(stream),  # type: ignore
                    )
        except OSError as ex:
            # TODO: report aioftp issue
            connection_refused = ex.errno == 111
            yield DownloadResponse(
                _stream=None,
                retry=connection_refused,
                error=(
                    "Received `Connection refused` error while downloading"
                    f" {source_path}. Retrying..."
                    if not connection_refused
                    else None
                ),
            )
