# SPDX-License-Identifer: GPL-3.0-or-later

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import aioftp  # type: ignore
from aioftp.errors import StatusCodeError  # type: ignore

from ..downloader import Downloader
from ..response import DownloadResponse


class FTPFileMissingException(Exception):
    pass


@dataclass
class FTPStat:
    size: int | None = None
    date: datetime | None = None


class FTPDownloader(Downloader):
    def iter_by_block(self, ftp: aioftp.Client, path: Path):
        async def func() -> AsyncIterator[bytes]:
            async with ftp.download_stream(path) as stream:  # type: ignore
                async for data in stream.iter_by_block(  # type: ignore
                    count=self.BUFFER_SIZE
                ):
                    yield data

        return func

    @asynccontextmanager
    async def stream(self, source_path: Path):
        try:
            async with aioftp.Client.context(  # type: ignore
                self._settings.url.hostname,
                port=self._settings.url.port or aioftp.DEFAULT_PORT,
                user=self._settings.url.username or aioftp.DEFAULT_USER,
                password=self._settings.url.password or aioftp.DEFAULT_PASSWORD,
                parse_list_line_custom_first=True,
                socket_timeout=30,
            ) as ftp:
                ftp.parse_list_line_custom = self.parse_list_line_unix_links(ftp)

                await ftp.change_directory(self._settings.url.path)

                try:
                    stat = await self._get_stat(ftp, source_path)
                except FTPFileMissingException:
                    yield DownloadResponse(_stream=None, missing=True)
                    return
                except StatusCodeError as ex:
                    yield DownloadResponse(_stream=None, error=str(ex))
                    return

                yield DownloadResponse(
                    missing=False,
                    error=None,
                    date=stat.date,
                    size=stat.size,
                    _stream=self.iter_by_block(ftp, source_path),  # type: ignore
                )
        except OSError as ex:
            # https://github.com/aio-libs/aioftp/issues/173
            connection_refused = ex.errno == 111 or "111" in str(ex)
            yield DownloadResponse(
                _stream=None,
                retry=connection_refused,
                error=(str(ex) if not connection_refused else None),
            )
        except Exception as ex:  # pylint: disable=W0718
            yield DownloadResponse(
                _stream=None,
                error=f"{ex.__class__.__qualname__}: {str(ex)}",
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

    async def _get_stat(
        self,
        ftp: aioftp.Client,
        path: Path,  # type: ignore
    ) -> FTPStat:  # type: ignore
        ftp_stat = FTPStat()

        try:
            stat: dict[str, str] = await ftp.stat(path)  # type: ignore

            recurse_depth = 5
            link_dst: str | None = stat.get("link_dst")  # type: ignore
            while link_dst and recurse_depth > 0:
                try:
                    path: Path = path.parent / link_dst  # type: ignore

                    stat = await ftp.stat(path)  # type: ignore
                    link_dst = stat.get("link_dst")  # type: ignore
                except StatusCodeError:
                    # Give up if we can not stat link destination
                    break

                recurse_depth -= 1

            if stat.get("type") != "file":  # type: ignore
                raise FTPFileMissingException()

            try:
                if not link_dst:  # type: ignore
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
            if isinstance(ex, FTPFileMissingException) or ex.received_codes[-1].matches(  # type: ignore
                "550"
            ):
                raise FTPFileMissingException() from ex
            else:
                raise

        return ftp_stat
