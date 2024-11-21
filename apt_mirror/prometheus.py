# SPDX-License-Identifer: GPL-3.0-or-later

from abc import ABC, abstractmethod
from collections.abc import Generator, Iterable
from typing import Any

from .download.downloader import Downloader
from .repository import BaseRepository


class BaseDownloaderCollector(ABC):
    def __init__(self, address: str, port: int) -> None:
        self._address = address
        self._port = port
        self._repositories: list[tuple[BaseRepository, Downloader]] = []

    def prometheus_available(self) -> bool:
        return False

    def shutdown(self):  # noqa: B027
        pass

    def add_downloader(self, repository: BaseRepository, downloader: Downloader):
        self._repositories.append((repository, downloader))

    @abstractmethod
    def collect(self) -> Iterable[Any]:
        pass


class DummyDownloaderCollector(BaseDownloaderCollector):
    def collect(self):
        yield


try:
    from prometheus_client import Metric, start_http_server
    from prometheus_client.core import REGISTRY, GaugeMetricFamily
    from prometheus_client.registry import Collector
except ImportError:

    class DownloaderCollector(DummyDownloaderCollector):
        pass

else:

    class DownloaderCollector(BaseDownloaderCollector, Collector):  # type: ignore
        def __init__(self, address: str, port: int) -> None:
            super().__init__(address, port)

            self._wsgi_server = None
            self._wsgi_thread = None

            wsgi_data = start_http_server(port=port, addr=address)
            if wsgi_data:
                self._wsgi_server, self._wsgi_thread = wsgi_data

            REGISTRY.register(self)

        def prometheus_available(self) -> bool:
            return True

        def shutdown(self):
            if self._wsgi_server:
                self._wsgi_server.shutdown()

                if self._wsgi_thread:
                    self._wsgi_thread.join()

        def _metric(self, name: str):
            mf = GaugeMetricFamily(
                f"apt_mirror_{name}",
                name.replace("_", " ").capitalize(),
                labels=["url"],
            )

            for repository, downloader in self._repositories:
                mf.add_metric(
                    [str(repository.url)],
                    value=getattr(downloader, name),
                )

            return mf

        def collect(self) -> Generator[Metric, Any, None]:
            yield self._metric("queue_files_count")
            yield self._metric("queue_files_size")
            yield self._metric("downloaded_files_count")
            yield self._metric("downloaded_files_size")
            yield self._metric("error_files_count")
            yield self._metric("error_files_size")
            yield self._metric("missing_files_count")
            yield self._metric("missing_files_size")
            yield self._metric("unmodified_files_count")
            yield self._metric("unmodified_files_size")
