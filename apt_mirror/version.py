# SPDX-License-Identifer: GPL-3.0-or-later

from importlib.metadata import PackageNotFoundError, version

try:
    # We use plain string here instead of `__package__` to make pyinstaller
    # distribution collection works.
    __version__ = version("apt_mirror")
except PackageNotFoundError:
    __version__ = "unknown"
