# SPDX-License-Identifer: GPL-3.0-or-later

from dataclasses import dataclass
from urllib import parse


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
