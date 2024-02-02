# SPDX-License-Identifer: GPL-3.0-or-later

import asyncio
import itertools
import os
import shutil
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, AsyncGenerator, AsyncIterator, Callable, Iterable, Sequence
from urllib import parse

import aioftp  # type: ignore
import httpx
from aiofile import async_open
from aioftp.client import Client, DataConnectionThrottleStreamIO  # type: ignore
from aioftp.errors import StatusCodeError  # type: ignore
from aiolimiter import AsyncLimiter

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


@dataclass
class Proxy:
    use_proxy: bool
    http_proxy: str | None
    https_proxy: str | None
    username: str | None
    password: str | None

    def for_scheme(self, scheme: str) -> str | None:
        if not self.use_proxy:
            return None

        if scheme == "http://" and self.http_proxy:
            return self.url_for_proxy(self.http_proxy)

        if scheme == "https://" and self.https_proxy:
            return self.url_for_proxy(self.https_proxy)

        return None

    def url_for_proxy(self, proxy: str) -> str:
        if "://" not in proxy:
            proxy = f"http://{proxy}"

        url = parse.urlparse(proxy)
        if self.username:
            auth = parse.quote(self.username, safe="")
            if self.password:
                auth = f"{auth}:{parse.quote(self.password, safe='')}"

            url = url._replace(netloc=f"{auth}@{url.netloc}")

        return parse.urlunparse(url)


class HashType(Enum):
    SHA512 = "SHA512"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5Sum"


@dataclass
class HashSum:
    type: HashType
    hash: str


class FileCompression(Enum):
    XZ = "xz"
    GZ = "gz"
    BZ2 = "bz2"
    NONE = None

    @staticmethod
    def all_compressed() -> Iterable["FileCompression"]:
        return (
            compression
            for compression in FileCompression
            if compression != FileCompression.NONE
        )

    @staticmethod
    def all_compressed_extensions() -> Iterable[str]:
        return (
            compression.file_extension
            for compression in FileCompression.all_compressed()
        )

    @property
    def file_extension(self) -> str:
        if self.value:
            return f".{self.value}"

        return ""


@dataclass
class DownloadFileCompressionVariant:
    path: Path
    compression: FileCompression
    size: int
    hashes: dict[HashType, HashSum]
    use_by_hash: bool

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

        if not self.use_by_hash:
            paths.append(self.path)

        if self.use_by_hash:
            paths += [
                self.path.parent / "by-hash" / hashsum.type.value / hashsum.hash
                for hashsum in self.hashes.values()
            ]

        if self.use_by_hash:
            paths.append(self.path)

        return paths


@dataclass
class DownloadFile:
    path: Path
    compression_variants: dict[FileCompression, DownloadFileCompressionVariant] = field(
        default_factory=lambda: {}
    )
    check_size: bool = False
    ignore_errors: bool = False

    @staticmethod
    def uncompressed_path(path: Path):
        if path.suffix in FileCompression.all_compressed_extensions():
            return path.with_suffix("")

        return path

    @classmethod
    def from_path(cls, path: Path, check_size: bool = False):
        return cls(path=path, check_size=check_size)

    @classmethod
    def from_hashed_path(
        cls,
        path: Path,
        size: int,
        hash_type: HashType,
        hash_sum: HashSum,
        use_by_hash: bool,
    ):
        download_file = DownloadFile.from_path(cls.uncompressed_path(path))
        download_file.add_compression_variant(
            path=path,
            size=size,
            hash_type=hash_type,
            hash_sum=hash_sum,
            use_by_hash=use_by_hash,
        )

        return download_file

    def __post_init__(self):
        if not self.compression_variants:
            self.add_compression_variant(self.path, size=0)

    def add_compression_variant(
        self,
        path: Path,
        size: int,
        hash_type: HashType | None = None,
        hash_sum: HashSum | None = None,
        use_by_hash: bool = False,
    ):
        hashes = {}
        if hash_type and hash_sum:
            hashes[hash_type] = hash_sum

        compression = FileCompression.NONE
        for _compression in FileCompression:
            if _compression.file_extension.lower() == path.suffix:
                compression = _compression
                break

        if compression == FileCompression.NONE:
            self.path = path

        compression_variant = self.compression_variants.setdefault(
            compression,
            DownloadFileCompressionVariant(
                path=path,
                compression=compression,
                size=size,
                hashes=hashes,
                use_by_hash=use_by_hash,
            ),
        )

        compression_variant.path = path
        compression_variant.size = size
        compression_variant.use_by_hash = use_by_hash
        compression_variant.hashes.update(hashes)

    def iter_variants(self):
        for compression in FileCompression:
            if compression in self.compression_variants:
                yield self.compression_variants[compression]

    @property
    def size(self):
        return next(iter(self.compression_variants.values())).size

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
        url: URL,
        *,
        target_root_path: Path,
        proxy: Proxy,
        user_agent: str,
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter | None = None,
        verify_ca_certificate: bool | str = True,
        client_certificate: str | None = None,
        client_private_key: str | None = None,
    ) -> "Downloader":
        if url.scheme.startswith("http"):
            cls = HTTPDownloader
        elif url.scheme.startswith("ftp"):
            cls = FTPDownloader
        else:
            raise UnsupportedURLException(f"Unsupported URL scheme: {url.scheme}")

        return cls(
            url=url,
            target_root_path=target_root_path,
            proxy=proxy,
            user_agent=user_agent,
            semaphore=semaphore,
            rate_limiter=rate_limiter,
            verify_ca_certificate=verify_ca_certificate,
            client_certificate=client_certificate,
            client_private_key=client_private_key,
        )

    def __init__(
        self,
        *,
        url: URL,
        target_root_path: Path,
        proxy: Proxy,
        user_agent: str,
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter | None = None,
        verify_ca_certificate: bool | str = True,
        client_certificate: str | None = None,
        client_private_key: str | None = None,
    ):
        self._log = get_logger(self)

        self._url = url
        self._target_root_path = target_root_path
        self._semaphore = semaphore
        self._rate_limiter = rate_limiter
        self._proxy = proxy
        self._user_agent = user_agent

        self._verify_ca_certificate = verify_ca_certificate
        self._client_certificate = client_certificate
        self._client_private_key = client_private_key

        # Download queue. Reseted in download()
        self._sources: list[DownloadFile] = []
        # Downloaded or not-changed files
        self._downloaded: list[DownloadFileCompressionVariant] = []
        # Either missing on server files or files with errors
        self._missing_sources: set[Path] = set()
        self._download_start = datetime.now()

        self.reset_stats()

        self.__post_init__()

    def __post_init__(self):
        pass

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

            file_actual = False
            if source_file.check_size:
                for variant in source_file.iter_variants():
                    target_path = self._target_root_path / variant.get_source_path()

                    try:
                        stat = target_path.stat()
                        if stat.st_size == source_file.size:
                            self._actual_count += 1
                            self._actual_size += source_file.size

                            self._downloaded.append(variant)

                            file_actual = True
                            break
                    except FileNotFoundError:
                        pass

            if file_actual:
                continue

            tasks.add(asyncio.create_task(self.download_file(source_file)))

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

    def need_update(self, path: Path, size: int | None, date: datetime | None) -> bool:
        if path.exists():
            if date and size:
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
                target_path = self._target_root_path / source_path

                tries = 10
                while tries > 0:
                    async with (
                        self._semaphore,
                        self.stream(source_path) as response,
                    ):
                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        if response.retry:
                            await retry(skip_try=True)
                            continue

                        if response.missing:
                            if source_file.ignore_errors:
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
                                f"Server reported size {response.size} is differs from"
                                f" expected size {expected_size} for file"
                                f" {source_path}. Retrying..."
                            )
                            error = True
                            continue

                        mirror_paths = [
                            self._target_root_path / path
                            for path in variant.get_all_paths()
                        ]

                        if response.size and not self.need_update(
                            target_path, response.size, response.date
                        ):
                            self._actual_count += 1
                            self._actual_size += response.size

                            if mirror_paths:
                                self.link_or_copy(target_path, *mirror_paths)

                            self._downloaded.append(variant)

                            return

                        size = 0
                        target_path.unlink(missing_ok=True)
                        async with async_open(target_path, "wb") as fp:
                            try:
                                async for chunk in response.stream():
                                    if self._rate_limiter:
                                        await self._rate_limiter.acquire(
                                            min(len(chunk), self._rate_limiter.max_rate)
                                        )

                                    size += len(chunk)
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
                        return

        if source_file.ignore_errors:
            self._log.info(f"Unable to download {source_file.path}: ignoring")
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


class HTTPDownloader(Downloader):
    def __post_init__(self):
        auth = None
        if self._url.username and self._url.password:
            auth = (self._url.username, self._url.password)

        base_url = str(self._url)
        if not base_url.endswith("/"):
            base_url += "/"

        proxy_mounts: dict[str, httpx.AsyncHTTPTransport] = {}
        for scheme in ("http://", "https://"):
            proxy_mounts[scheme] = httpx.AsyncHTTPTransport(
                verify=self._verify_ca_certificate,
                http1=True,
                http2=True,
                limits=httpx.Limits(
                    max_connections=256,
                    max_keepalive_connections=32,
                    keepalive_expiry=5,
                ),
                proxy=self._proxy.for_scheme(scheme),
                retries=5,
            )

        client_certificate = None
        if self._client_certificate:
            if self._client_private_key:
                client_certificate = (
                    self._client_certificate,
                    self._client_private_key,
                )
            else:
                client_certificate = self._client_certificate

        self._httpx = httpx.AsyncClient(
            base_url=base_url,
            auth=auth,
            timeout=None,
            follow_redirects=True,
            mounts=proxy_mounts,
            transport=httpx.AsyncHTTPTransport(
                verify=self._verify_ca_certificate,
                cert=client_certificate,
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
                "User-Agent": self._user_agent,
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
                except (TypeError, ValueError):
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


@dataclass
class FTPStat:
    size: int | None = None
    date: datetime | None = None


class FTPDownloader(Downloader):
    def iter_by_block(self, stream: aioftp.DataConnectionThrottleStreamIO):
        def func() -> AsyncIterator[bytes]:
            return stream.iter_by_block(count=self.BUFFER_SIZE)  # type: ignore

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
                parse_list_line_custom_first=True,
            ) as ftp:
                ftp.parse_list_line_custom = self.parse_list_line_unix_links(ftp)

                await ftp.change_directory(self._url.path)

                try:
                    stat = await self._get_stat(ftp, source_path)
                except FTPFileMissingException:
                    yield DownloadResponse(_stream=None, missing=True)
                    return
                except StatusCodeError as ex:
                    yield DownloadResponse(_stream=None, error=str(ex))
                    return

                stream: aioftp.DataConnectionThrottleStreamIO
                async with ftp.download_stream(source_path) as stream:  # type: ignore
                    yield DownloadResponse(
                        missing=False,
                        error=None,
                        date=stat.date,
                        size=stat.size,
                        _stream=self.iter_by_block(stream),  # type: ignore
                    )
        except OSError as ex:
            # https://github.com/aio-libs/aioftp/issues/173
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

    def parse_list_line_unix_links(self, client: aioftp.Client):
        def do_parse_list_line(b: bytes) -> tuple[PurePosixPath, dict[str, str]]:
            info: dict[str, str]
            path, info = client.parse_list_line_unix(b)  # type: ignore

            s = b.decode(encoding=client.encoding).rstrip()
            if s[0] == "l":
                i = s.rindex(" -> ")
                info["link_dst"] = s[i + 4 :]

            return path, info

        return do_parse_list_line

    async def _get_stat(self, ftp: Client, path: Path) -> FTPStat:  # type: ignore
        ftp_stat = FTPStat()

        try:
            stat: dict[str, str] = await ftp.stat(path)  # type: ignore

            recurse_depth = 5
            link_dst: str | None = stat.get("link_dst")  # type: ignore
            while link_dst and recurse_depth > 0:
                try:
                    path: Path = path.parent / link_dst  # type: ignore
                    stat = await ftp.stat(path)  # type: ignore
                except StatusCodeError:
                    # Give up if we can not stat link destination
                    break

                recurse_depth -= 1

            if stat.get("type") != "file":  # type: ignore
                raise FTPFileMissingException()

            try:
                if not stat.get("link_dst"):  # type: ignore
                    ftp_stat.size = int(stat["size"])  # type: ignore

                modify, _, _ = stat["modify"].partition(".")  # type: ignore
                if len(modify) == 14:  # type: ignore
                    ftp_stat.date = datetime.strptime(
                        modify,  # type: ignore
                        "%Y%m%d%H%M%S",
                    ).replace(tzinfo=timezone.utc)

            except (AttributeError, KeyError, ValueError):
                pass
        except (StatusCodeError, FTPFileMissingException) as ex:
            if isinstance(ex, FTPFileMissingException) or ex.received_codes[
                -1
            ].matches(  # type: ignore
                "550"
            ):
                raise FTPFileMissingException() from ex
            else:
                raise

        return ftp_stat
