# SPDX-License-Identifer: GPL-3.0-or-later

from contextlib import asynccontextmanager
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

from ..downloader import Downloader
from ..response import DownloadResponse


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
            timeout=httpx.Timeout(
                15,
                connect=30,
                read=60,
            ),
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
                "Accept-Encoding": "identity",
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
