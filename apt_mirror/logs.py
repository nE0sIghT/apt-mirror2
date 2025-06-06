# SPDX-License-Identifer: GPL-3.0-or-later

import logging
import os
import sys
from pathlib import PurePath
from typing import Any


class LoggerFactory:
    DEFAULT_LOGLEVEL = getattr(
        logging,
        os.getenv("APT_MIRROR_LOGLEVEL", "info").upper(),
    )
    DEFAULT_FORMAT = (
        "%(asctime)s: [%(process)d] %(levelname)s %(name_abbr)s %(message)s"
    )
    FILES: dict[Any, PurePath] = {}
    FILE_HANDLERS: dict[Any, logging.FileHandler] = {}
    FILE_MODE = "w"

    @staticmethod
    def init_logging():
        logging.basicConfig(
            format=LoggerFactory.DEFAULT_FORMAT,
            level=LoggerFactory.DEFAULT_LOGLEVEL,
            stream=sys.stderr,
        )
        logging.getLogger().handlers[0].addFilter(NameAbbrFilter())

        if LoggerFactory.DEFAULT_LOGLEVEL != logging.DEBUG:
            logging.getLogger("httpx").setLevel(logging.WARNING)

        logging.debug("Logging started")

    @staticmethod
    def enable_append_logs():
        LoggerFactory.FILE_MODE = "a"

    @staticmethod
    def get_logger(
        obj: Any,
        logger_id: Any | None = None,
    ) -> logging.Logger:
        log_name = (
            ".".join((obj.__class__.__module__, obj.__class__.__qualname__))
            if not isinstance(obj, str)
            else obj
        )

        log = logging.getLogger(
            f"{log_name}.{hash(logger_id)}" if logger_id else log_name
        )
        log.name = log_name
        log.level = LoggerFactory.DEFAULT_LOGLEVEL

        if logger_id in LoggerFactory.FILES:
            if logger_id not in LoggerFactory.FILE_HANDLERS:
                file_handler = logging.FileHandler(
                    LoggerFactory.FILES[logger_id],
                    mode=LoggerFactory.FILE_MODE,
                    encoding="utf-8",
                )
                file_handler.setFormatter(
                    logging.Formatter(LoggerFactory.DEFAULT_FORMAT)
                )
                file_handler.addFilter(NameAbbrFilter())

                LoggerFactory.FILE_HANDLERS[logger_id] = file_handler

            log.addHandler(LoggerFactory.FILE_HANDLERS[logger_id])

        return log

    @staticmethod
    def add_log_file(logger_id: Any, file: PurePath):
        LoggerFactory.FILES[logger_id] = file


class NameAbbrFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        modules = record.name.split(".")
        record.name_abbr = ".".join(
            ["_".join(p[:1] for p in m.split("_")) for m in modules[:-1]]
            + [modules[-1]]
        )

        return True


LoggerFactory.init_logging()
