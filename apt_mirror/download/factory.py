# SPDX-License-Identifer: GPL-3.0-or-later


from .downloader import Downloader, DownloaderSettings
from .protocols.ftp import FTPDownloader
from .protocols.http import HTTPDownloader


class UnsupportedURLException(ValueError):
    pass


class DownloaderFactory:
    @staticmethod
    def for_settings(*, settings: DownloaderSettings) -> Downloader:
        if settings.url.scheme.startswith("http"):
            cls = HTTPDownloader
        elif settings.url.scheme.startswith("ftp"):
            cls = FTPDownloader
        else:
            raise UnsupportedURLException(
                f"Unsupported URL scheme: {settings.url.scheme}"
            )

        return cls(settings=settings)
