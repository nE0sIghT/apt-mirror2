import os
import platform
from unittest import IsolatedAsyncioTestCase

from caio import linux_aio_asyncio, thread_aio_asyncio


class TestAIOFile(IsolatedAsyncioTestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self._platform = platform.system().lower()

    def linux_aio_supported(self):
        # For some reason AIO doesn't works on s390x
        # We hit it in the Debian's CI and I observe it in the s390x docker image
        # https://ci.debian.net/packages/a/apt-mirror2/testing/s390x/59830526/
        if "linux" not in self._platform or os.uname().machine == "s390x":
            return False

        if platform.python_implementation() != "CPython":
            return False

        return True

    def thread_aio_supported(self):
        if "linux" not in self._platform and "darwin" not in self._platform:
            return False

        if platform.python_implementation() != "CPython":
            return False

    async def test_linux_aio(self):
        if not self.linux_aio_supported():
            return

        async with linux_aio_asyncio.AsyncioContext() as _:
            pass

    async def test_thread_aio(self):
        if not self.thread_aio_supported():
            return

        async with thread_aio_asyncio.AsyncioContext() as _:
            pass
