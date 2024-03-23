# SPDX-License-Identifer: GPL-3.0-or-later

import asyncio
from pathlib import Path

from aiolimiter import AsyncLimiter

from .downloader import Downloader
from .protocols.ftp import FTPDownloader
from .protocols.http import HTTPDownloader
from .proxy import Proxy
from .url import URL


class UnsupportedURLException(ValueError):
    pass


class DownloaderFactory:
    @staticmethod
    def for_url(
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
    ) -> Downloader:
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
