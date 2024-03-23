# SPDX-License-Identifer: GPL-3.0-or-later

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version(__package__)
except PackageNotFoundError:
    __version__ = "unknown"
