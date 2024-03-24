# SPDX-License-Identifer: GPL-3.0-or-later

import re
from abc import ABC, abstractmethod
from threading import Thread
from typing import Any, Generator, Iterable

from .download.downloader import Downloader
from .repository import BaseRepository


class BaseDownloaderCollector(ABC):
    @classmethod
    @abstractmethod
    def register(cls, downloader: Downloader, repository: BaseRepository): ...

    def __init__(self, downloader: Downloader, repository: BaseRepository) -> None:
        self._downloader = downloader
        self._repository = repository

    @staticmethod
    def prometheus_available() -> bool:
        return False

    @staticmethod
    def init_server(address: str, port: int):
        pass

    @staticmethod
    def shutdown_server():
        pass

    @abstractmethod
    def collect(self) -> Iterable[Any]:
        pass


try:
    from wsgiref.simple_server import WSGIServer

    from prometheus_client import Metric, start_http_server
    from prometheus_client.core import REGISTRY, GaugeMetricFamily
    from prometheus_client.registry import Collector

    wsgi_server: WSGIServer | None = None
    wsgi_thread: Thread | None = None

    class DownloaderCollector(BaseDownloaderCollector, Collector):  # type: ignore
        @classmethod
        def register(cls, downloader: Downloader, repository: BaseRepository):
            REGISTRY.register(cls(downloader, repository))

        @staticmethod
        def prometheus_available() -> bool:
            return True

        @staticmethod
        def init_server(address: str, port: int):
            global wsgi_server, wsgi_thread
            wsgi_server, wsgi_thread = start_http_server(port=port, addr=address)

        @staticmethod
        def shutdown_server():
            if wsgi_server:
                wsgi_server.shutdown()

                if wsgi_thread:
                    wsgi_thread.join()

        def get_metric_id(self):
            return re.sub(
                r"(?i)[^a-z0-9_]", "_", str(self._repository.as_filename(False))
            )

        def collect(self) -> Generator[Metric, Any, None]:
            metric_id = f"mirror_{self.get_metric_id()}"

            mf = GaugeMetricFamily(
                f"{metric_id}",
                f"{self._repository.url} metrics",
                labels=["item", "url"],
            )

            mf.add_metric(
                ["queue_files_count", str(self._repository.url)],
                value=self._downloader.queue_files_count,
            )
            mf.add_metric(["queue_files_size"], value=self._downloader.queue_files_size)

            mf.add_metric(
                ["downloaded_files_count", str(self._repository.url)],
                value=self._downloader.downloaded_files_count,
            )
            mf.add_metric(
                ["downloaded_files_size", str(self._repository.url)],
                value=self._downloader.downloaded_files_size,
            )

            mf.add_metric(
                ["error_files_count", str(self._repository.url)],
                value=self._downloader.error_files_count,
            )
            mf.add_metric(
                ["error_files_size", str(self._repository.url)],
                value=self._downloader.error_files_size,
            )

            mf.add_metric(
                ["missing_files_count", str(self._repository.url)],
                value=self._downloader.missing_files_count,
            )
            mf.add_metric(
                ["missing_files_size", str(self._repository.url)],
                value=self._downloader.missing_files_size,
            )

            mf.add_metric(
                ["unmodified_count", str(self._repository.url)],
                value=self._downloader.unmodified_files_count,
            )
            mf.add_metric(
                ["unmodified_size", str(self._repository.url)],
                value=self._downloader.unmodified_files_size,
            )

            yield mf

except ImportError:

    class DownloaderCollector(BaseDownloaderCollector):
        @classmethod
        def register(cls, downloader: Downloader, repository: BaseRepository):
            pass

        def collect(self):
            yield
