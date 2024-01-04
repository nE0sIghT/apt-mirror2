# SPDX-License-Identifer: GPL-3.0-or-later

import logging
import os
import sys
from typing import Any

DEFAULT_LOGLEVEL = getattr(
    logging,
    os.getenv("APT_MIRROR_LOGLEVEL", "info").upper(),
)


def get_logger(obj: Any):
    log = logging.getLogger(
        ".".join((obj.__class__.__module__, obj.__class__.__qualname__))
        if not isinstance(obj, str)
        else obj
    )
    log.level = DEFAULT_LOGLEVEL

    return log


class NameAbbrFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        modules = record.name.split(".")
        record.name_abbr = ".".join(
            ["_".join(p[:1] for p in m.split("_")) for m in modules[:-1]]
            + [modules[-1]]
        )

        return True


logging.basicConfig(
    format="%(asctime)s: [%(process)d] %(levelname)s %(name_abbr)s %(message)s",
    level=DEFAULT_LOGLEVEL,
    stream=sys.stderr,
)
logging.getLogger().handlers[0].addFilter(NameAbbrFilter())

if DEFAULT_LOGLEVEL != logging.DEBUG:
    logging.getLogger("httpx").setLevel(logging.WARNING)

logging.debug("Logging started")
