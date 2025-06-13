# SPDX-License-Identifer: GPL-3.0-or-later

import argparse
import asyncio
import errno
import itertools
import os
import shutil
import signal
import sys
from collections.abc import Awaitable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from errno import EWOULDBLOCK
from fcntl import LOCK_EX, LOCK_NB, flock
from pathlib import Path
from typing import IO, Any

from aiolimiter import AsyncLimiter

from .aiofile import AsyncIOFileFactory, BaseAsyncIOFileWriterFactory
from .config import Config
from .download import (
    Downloader,
    DownloaderFactory,
    DownloadFile,
    DownloadFileCompressionVariant,
    HashType,
)
from .download.downloader import DownloaderSettings
from .download.format import format_size
from .logs import LoggerFactory
from .prometheus import (
    BaseDownloaderCollector,
    DownloaderCollector,
    DummyDownloaderCollector,
)
from .repository import BaseRepository, InvalidReleaseFilesException
from .uvloop import UVLOOP_AVAILABLE
from .uvloop import run as uvloop_run
from .version import __version__

LOG = LoggerFactory.get_logger(__package__)


class PathCleaner:
    def __init__(
        self,
        root_path: Path,
        keep_files: set[Path],
        wipe_size_ratio: float | None = None,
        wipe_count_ratio: float | None = None,
        logger_id: Any | None = None,
    ) -> None:
        self._log = LoggerFactory.get_logger(self, logger_id=logger_id)

        self._root_path = root_path

        self._wipe_size_ratio = wipe_size_ratio
        self._wipe_count_ratio = wipe_count_ratio

        self._bytes_cleaned = 0
        self._bytes_total = 0
        self._files_count = 0
        self._fp = None

        self._files_queue: list[Path] = []
        self._folders_queue: list[Path] = []
        self._keep_files = keep_files

        self._check_folder(self._root_path)

    def _check_folder(self, path: Path) -> bool:
        if path.relative_to(self._root_path) in self._keep_files:
            return True

        is_needed = False

        for file in path.glob("*"):
            if file.is_symlink():
                is_needed = True
                continue

            if file.is_file():
                is_needed |= self._check_file(file)

            if file.is_dir():
                is_needed |= self._check_folder(file)

        if not is_needed and path != self._root_path:
            self._folders_queue.append(path)

        return is_needed

    def _check_file(self, path: Path) -> bool:
        self._files_count += 1
        file_size = path.stat().st_size
        self._bytes_total += file_size

        if path.relative_to(self._root_path) in self._keep_files:
            return True

        self._bytes_cleaned += file_size
        self._files_queue.append(path)

        return False

    def _clean_allowed(self) -> bool:
        if (
            self._wipe_size_ratio
            and self.bytes_cleaned / self.bytes_total >= self._wipe_size_ratio
        ):
            return False

        if (
            self._wipe_count_ratio
            and self.clean_files_count / self.total_files_count
            >= self._wipe_count_ratio
        ):
            return False

        return True

    @property
    def bytes_cleaned(self):
        return self._bytes_cleaned

    @property
    def bytes_total(self):
        return self._bytes_total

    @property
    def clean_files_count(self):
        return len(self._files_queue)

    @property
    def total_files_count(self):
        return self._files_count

    @property
    def folders_count(self):
        return len(self._folders_queue)

    def write_clean_script(self, fp: IO[str], repository: BaseRepository):
        fp.write(
            "\n".join(
                [
                    "#!/bin/bash",
                    "set -e",
                    "",
                ]
            )
        )

        if not self._clean_allowed():
            self._log_wipe_threashold_warning()
            fp.write("echo ")
            fp.write(self._wipe_threashold_warning())
            fp.write(os.linesep)
            return

        fp.write(
            "\n".join(
                [
                    (
                        f"echo 'Removing {len(self._files_queue)}"
                        f" [{format_size(self._bytes_cleaned)}]"
                        f" unnecessary files and {len(self._folders_queue)} unnecessary"
                        f" folders in the repository {repository.url}...'"
                    ),
                    "",
                ]
                + [""]
            )
        )

        for file in self._files_queue:
            fp.write(f"rm -f '{file.absolute()}'\n")

        for folder in self._folders_queue:
            fp.write(f"rm -r '{folder.absolute()}'\n")

    def _wipe_threashold_warning(self) -> str:
        return (
            "Wipe threshold reached. Clean will not be performed. Total size:"
            f" {format_size(self.bytes_total)}, about to clean:"
            f" {format_size(self.bytes_cleaned)}. Total files:"
            f" {self.total_files_count}, about to clean: {self.clean_files_count}."
        )

    def _log_wipe_threashold_warning(self):
        self._log.warning(self._wipe_threashold_warning())

    def clean(self):
        if not self._clean_allowed():
            self._log_wipe_threashold_warning()
            return

        for file in self._files_queue:
            file.unlink(missing_ok=True)

        for folder in self._folders_queue:
            folder.rmdir()

        self._log.info(
            "Removed"
            f" {len(self._files_queue)} [{format_size(self._bytes_cleaned)}]"
            f" unnecessary files and {len(self._folders_queue)} unnecessary folders"
        )


class RepositoryMirror:
    MOVE_FOLDER_PREFIX = ".apt_mirror_"
    MOVE_FOLDER_OLD_SUFFIX = f"{MOVE_FOLDER_PREFIX}old"
    MOVE_FOLDER_NEW_SUFFIX = f"{MOVE_FOLDER_PREFIX}new"

    @classmethod
    async def create(
        cls,
        repository: BaseRepository,
        config: Config,
        semaphore: asyncio.Semaphore,
        download_semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter | None,
        metrics_collector: BaseDownloaderCollector,
    ):
        skel_path = config.skel_path / repository.get_mirror_path(config.encode_tilde)
        mirror_path = config.mirror_path / repository.get_mirror_path(
            config.encode_tilde
        )
        test_file = ".apt_mirror_aio"
        asyncio_file_factory = await AsyncIOFileFactory.create(
            skel_path / test_file,
            mirror_path / test_file,
        )

        return cls(
            repository,
            config,
            asyncio_file_factory,
            semaphore,
            download_semaphore,
            rate_limiter,
            metrics_collector,
        )

    def __init__(
        self,
        repository: BaseRepository,
        config: Config,
        asyncio_file_factory: BaseAsyncIOFileWriterFactory,
        semaphore: asyncio.Semaphore,
        download_semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter | None,
        metrics_collector: BaseDownloaderCollector,
    ) -> None:
        self._log = LoggerFactory.get_logger(self, logger_id=repository.url)

        self._error = False

        self._repository = repository
        self._pool_folders: set[Path] = set()

        self._config = config
        self._download_semaphore = download_semaphore
        self._semaphore = semaphore
        self._rate_limiter = rate_limiter

        self._downloader = DownloaderFactory.for_settings(
            settings=DownloaderSettings(
                url=self._repository.url,
                target_root_path=config.skel_path
                / repository.get_mirror_path(config.encode_tilde),
                aiofile_factory=asyncio_file_factory,
                proxy=self._config.proxy,
                http2_disable=repository.http2_disable,
                user_agent=self._config.user_agent,
                semaphore=self._download_semaphore,
                slow_rate_protector_factory=self._config.slow_rate_protector_factory,
                rate_limiter=self._rate_limiter,
                verify_ca_certificate=self._config.verify_ca_certificate,
                client_certificate=self._config.client_certificate,
                client_private_key=self._config.client_private_key,
            ),
        )

        metrics_collector.add_downloader(self._repository, self._downloader)

    async def mirror(self) -> bool:
        """Start repository mirror process

        Returns:
            bool: True if mirror was successful, False otherwise
        """
        async with self._semaphore:
            self._log.info(f"Mirroring repository {self._repository}")

            release_files = await self.download_release_files()
            if not release_files:
                self._log.error(
                    f"Unable to obtain release files for repository {self._repository}"
                )
                return False

            # Download other metadata files
            metadata_files = await self.download_metadata_files()
            if not metadata_files:
                self._log.error(
                    f"Unable to obtain metadata files for repository {self._repository}"
                )
                return False

            downloaded_metadata_files = self._downloader.get_all_files()

            await self.clean_repository_skel(
                set(
                    itertools.chain.from_iterable(
                        v.get_all_paths() for v in downloaded_metadata_files
                    )
                )
                - self._downloader.get_missing_sources(),
            )

            # Download remaining pool
            await self.download_pool_files()

            # Move skel to mirror
            if not self._error:
                await self.move_metadata(downloaded_metadata_files)
            else:
                self._log.warning(
                    "Metadata movement skipped because of download errors"
                )

            if self._repository.clean:
                if not self._error:
                    await self.clean_repository(
                        needed_files=self._downloader.get_downloaded_files_paths(),
                        unlink=self._config.autoclean,
                    )
                else:
                    self._log.warning(
                        "Repository cleanup skipped because of download errors"
                    )

            self._log.info(f"Repository {self._repository} mirroring complete")

        return not self._error

    async def download_release_files(self) -> Sequence[DownloadFile]:
        # Download release files
        self._log.info(f"Downloading release files for repository {self._repository}")
        release_files = [
            DownloadFile.from_path(path, ignore_missing=True)
            for path in self._repository.release_files
        ]

        tries = self._config.release_files_retries
        while True:
            self._downloader.reset_paths()
            self._downloader.add(*release_files)
            await self._downloader.download()

            # Drop release files in skel which we were unable to download
            downloaded_paths = self._downloader.get_downloaded_files_paths()
            for relative_path in self._repository.release_files:
                path = (
                    self._config.skel_path
                    / self._repository.get_mirror_path(self._config.encode_tilde)
                    / relative_path
                )

                if path.exists() and relative_path not in downloaded_paths:
                    path.unlink()

            # Check release files
            try:
                self._repository.validate_release_files(
                    self._config.skel_path,
                    self._config.encode_tilde,
                    self._config.etc_trusted,
                    self._config.etc_trusted_parts,
                )
                break
            except InvalidReleaseFilesException as ex:
                self._log.warning(f"Release files are invalid: {ex}. Retrying...")
                tries -= 1

                if tries < 1:
                    return []

                await asyncio.sleep(5)

        # Fail in case we have download errors, but don't complain for missing files
        if self._downloader.has_errors():
            self._error = True

        return release_files

    async def download_metadata_files(self) -> Iterable[DownloadFile]:
        metadata_files = self._repository.get_metadata_files(
            self._config.skel_path,
            self._config.encode_tilde,
            self._downloader.get_missing_sources(),
        )

        if not metadata_files:
            self._error = True
            return metadata_files

        self._downloader.add(*metadata_files)

        self._log.info(
            f"Downloading {self._downloader.queue_files_count} metadata files for"
            f" repository {self._repository}. Total size is"
            f" {self._downloader.queue_files_formatted_size}"
        )

        await self._downloader.download()

        if self._downloader.has_errors() or self._downloader.has_missing():
            self._error = True

        return metadata_files

    async def download_pool_files(self) -> Iterable[DownloadFile]:
        self._downloader.set_target_path(
            self._config.mirror_path
            / self._repository.get_mirror_path(self._config.encode_tilde)
        )

        self._log.info(f"Processing metadata for repository {self._repository}")
        with ThreadPoolExecutor(max_workers=1) as executor:
            pool_files = await asyncio.get_running_loop().run_in_executor(
                executor,
                self._repository.get_pool_files,
                self._config.skel_path,
                self._config.encode_tilde,
                self._downloader.get_missing_sources(),
            )

        self._downloader.add(*pool_files)

        self._log.info(
            f"Downloading {self._downloader.queue_files_count} pool files for"
            f" repository {self._repository}. Total size is"
            f" {self._downloader.queue_files_formatted_size}"
        )

        await self._downloader.download()

        if self._downloader.has_errors() or self._downloader.has_missing():
            self._error = True

        self._pool_folders = {
            p.parents[-2]
            for f in pool_files
            for v in f.compression_variants.values()
            for p in v.get_all_paths()
            if len(p.parents) > 1
        }

        return pool_files

    async def move_metadata(
        self,
        metadata_files: Iterable[DownloadFileCompressionVariant],
    ):
        self._log.info("Moving metadata")
        mirror_path = self._repository.get_mirror_path(self._config.encode_tilde)
        mirror_full_path = self._config.mirror_path / mirror_path

        move_folders: set[Path] = set()

        # Drop any temporary leftovers
        for folder in mirror_full_path.glob(f"*{self.MOVE_FOLDER_PREFIX}*"):
            if not folder.is_dir():
                continue

            self._rmtree(folder)

        for file in metadata_files:
            file_alternate_paths: list[Path] = []
            file_skel_path = self._config.skel_path / mirror_path / file.path

            if (
                len(file.path.parents) > 1
                and file.path.parents[-2] not in self._pool_folders
            ):
                # Get first level directory
                top_parent = file.path.parents[-2]
                top_parent_new_path = top_parent.with_name(
                    f"{top_parent.name}{self.MOVE_FOLDER_NEW_SUFFIX}"
                )

                for file_path in file.get_all_paths():
                    if file_path.is_relative_to(top_parent):
                        file_alternate_paths.append(
                            mirror_full_path
                            / top_parent_new_path
                            / file_path.relative_to(top_parent)
                        )
                    else:
                        file_alternate_paths.append(mirror_full_path / file_path)

                move_folders.add(top_parent)
            else:
                file_alternate_paths = [
                    mirror_full_path / f for f in file.get_all_paths()
                ]

            if file_skel_path.exists():
                Downloader.link_or_copy(
                    file_skel_path,
                    *file_alternate_paths,
                )

        for top_parent in move_folders:
            mirror_parent_path = mirror_full_path / top_parent

            mirror_parent_old_path = mirror_full_path / top_parent.with_name(
                f"{top_parent.name}{self.MOVE_FOLDER_OLD_SUFFIX}"
            )
            mirror_parent_new_path = mirror_full_path / top_parent.with_name(
                f"{top_parent.name}{self.MOVE_FOLDER_NEW_SUFFIX}"
            )

            if not mirror_parent_new_path.exists():
                continue

            # Move dists > dists.apt_mirror_old
            if mirror_parent_path.exists():
                if mirror_parent_old_path.exists():
                    self._rmtree(mirror_parent_old_path)

                shutil.move(
                    mirror_parent_path,
                    mirror_parent_old_path,
                )

            # Move dists.apt_mirror_new > dists
            shutil.move(
                mirror_parent_new_path,
                mirror_parent_path,
            )

            # Drop dists.apt_mirror_old
            if mirror_parent_old_path.exists():
                self._rmtree(mirror_parent_old_path)

        self._log.info("Metadata moved")

    async def clean_repository(self, needed_files: set[Path], unlink: bool):
        cleaner = PathCleaner(
            self._config.mirror_path
            / self._repository.get_mirror_path(self._config.encode_tilde),
            needed_files | self._repository.skip_clean,
            wipe_size_ratio=self._config.wipe_size_ratio,
            wipe_count_ratio=self._config.wipe_count_ratio,
            logger_id=self._repository.url,
        )

        if unlink:
            self._log.info(f"Cleaning repository {self._repository}")
            cleaner.clean()
        else:
            self._log.info(f"Creating clean script for repository {self._repository}")
            clean_script = (
                self._config.cleanscript.parent
                / self._repository.get_clean_script_name(self._config.encode_tilde)
            )
            with open(
                clean_script,
                "wt",
                encoding="utf-8",
            ) as fp:
                cleaner.write_clean_script(fp, repository=self._repository)

            clean_script.chmod(0o750)

    async def clean_repository_skel(self, needed_files: set[Path]):
        self._log.info(f"Cleaning skel folder for repository {self._repository}")

        cleaner = PathCleaner(
            self._config.skel_path
            / self._repository.get_mirror_path(self._config.encode_tilde),
            needed_files,
            logger_id=self._repository.url,
        )

        cleaner.clean()

    def get_repository(self) -> BaseRepository:
        return self._repository

    def get_downloaded_files(self) -> list[DownloadFileCompressionVariant]:
        return self._downloader.get_downloaded_files()

    def get_unmodified_files(self) -> list[DownloadFileCompressionVariant]:
        return self._downloader.get_unmodified_files()

    def _rmtree(self, path: Path):
        max_tries = 5

        while path.exists():
            try:
                shutil.rmtree(path)
            except OSError as e:
                max_tries -= 1
                if max_tries < 0:
                    raise e

                if e.errno == errno.ENOTEMPTY and e.filename:
                    non_empty_path = Path(e.filename)

                    if non_empty_path.is_relative_to(path):
                        shutil.rmtree(non_empty_path, ignore_errors=True)


class APTMirror:
    LOCK_FILE = "apt-mirror.lock"

    def __init__(self, config: Config) -> None:
        self.stopped = False

        self._log = LoggerFactory.get_logger(self)
        self._config = config
        self._lock_fd = None

        self._semaphore = asyncio.Semaphore(self._config.nthreads)
        self._download_semaphore = asyncio.Semaphore(self._config.nthreads)

        self._error: bool = False

        self._rate_limiter = None
        if self._config.limit_rate:
            self._rate_limiter = AsyncLimiter(self._config.limit_rate * 60, 60)

        if self._config.prometheus_enable:
            self._metrics_collector = DownloaderCollector(
                self._config.prometheus_host, self._config.prometheus_port
            )
            if not self._metrics_collector.prometheus_available():
                self._log.warning("Prometheus python client is not available")
        else:
            self._metrics_collector = DummyDownloaderCollector(
                self._config.prometheus_host, self._config.prometheus_port
            )

    def on_stop(self):
        self.stopped = True
        self._metrics_collector.shutdown()
        asyncio.get_running_loop().stop()

    async def run(self) -> int:
        self._log.info(f"apt-mirror2 version {__version__}")
        signal.signal(signal.SIGTERM, lambda _, __: self.on_stop())

        if not self._config.repositories:
            self._log.error("No repositories are found in the configuration")
            return 2

        with self.lock():
            tasks: list[Awaitable[bool]] = []
            mirrors: list[RepositoryMirror] = []
            for repository in self._config.repositories.values():
                mirror = await RepositoryMirror.create(
                    repository,
                    self._config,
                    self._semaphore,
                    self._download_semaphore,
                    self._rate_limiter,
                    self._metrics_collector,
                )
                tasks.append(asyncio.create_task(mirror.mirror()))
                mirrors.append(mirror)

            self._error = not all(await asyncio.gather(*tasks))

            if not self._config.autoclean and any(
                r.clean for r in self._config.repositories.values()
            ):
                self._log.info(f"Writing clean script {self._config.cleanscript}")
                with open(self._config.cleanscript, "wt", encoding="utf-8") as fp:
                    fp.write(
                        "\n".join(
                            [
                                "#!/bin/sh",
                                "set -e",
                                "",
                            ]
                        )
                    )

                    for repository in self._config.repositories.values():
                        if not repository.clean:
                            continue

                        clean_script = (
                            self._config.cleanscript.parent
                            / repository.get_clean_script_name(
                                self._config.encode_tilde
                            )
                        )
                        fp.write(f"sh '{clean_script}'\n")

                self._config.cleanscript.chmod(0o750)

            if self._config.write_file_lists:
                with ExitStack() as stack:
                    fp_all = stack.enter_context(
                        open(self._config.var_path / "ALL", "wt", encoding="utf-8")
                    )
                    fp_new = stack.enter_context(
                        open(self._config.var_path / "NEW", "wt", encoding="utf-8")
                    )

                    fp_hash_types: dict[HashType, IO[str]] = {}
                    for hash_type in HashType:
                        fp_hash_types[hash_type] = stack.enter_context(
                            open(
                                self._config.var_path / hash_type.name,
                                "wt",
                                encoding="utf-8",
                            )
                        )

                    for mirror in mirrors:
                        for download_variant in mirror.get_downloaded_files():
                            fp_all.write(f"{download_variant.path}{os.linesep}")
                            fp_new.write(
                                mirror.get_repository().url.for_path(
                                    download_variant.path
                                )
                                + os.linesep
                            )

                            self._write_hashsums(fp_hash_types, download_variant)

                        for download_variant in mirror.get_unmodified_files():
                            self._write_hashsums(fp_hash_types, download_variant)

            if self._config.run_postmirror:
                if not self._config.postmirror_script.is_file():
                    self._log.error(
                        "Post Mirror script is missing: "
                        f"{self._config.postmirror_script}"
                    )
                else:
                    self._log.info(
                        "Running the Post Mirror script"
                        f" {self._config.postmirror_script}..."
                    )
                    args = [self._config.postmirror_script]
                    if not os.access(self._config.postmirror_script, os.X_OK):
                        args = ["/bin/sh"] + args

                    process = await asyncio.create_subprocess_exec(
                        *args,
                        stdout=None,
                        stderr=None,
                        env=self._config.as_environment(),
                    )
                    await process.wait()

                    self._log.info(
                        "Post Mirror script has completed. See above output for any"
                        " possible errors."
                    )

            self._metrics_collector.shutdown()

        if self._error:
            self._log.error(
                "Some files were not downloaded. Please check logs above for details."
            )
            return 1

        return 0

    def die(self, message: str, code: int = 1):
        self._log.error(message)
        sys.exit(code)

    def get_lock_file(self):
        return self._config.var_path / self.LOCK_FILE

    @contextmanager
    def lock(self):
        lock_file = self.get_lock_file()
        with open(lock_file, "wb") as fp:
            try:
                flock(fp, LOCK_EX | LOCK_NB)
                yield
            except OSError as ex:
                if ex.errno == EWOULDBLOCK:
                    self.die("apt-mirror is already running, exiting")

                strerror = os.strerror(ex.errno) if ex.errno else "unknown error"
                self.die(
                    f"Unable to obtain lock on {lock_file}: error {ex.errno}:"
                    f" {strerror}"
                )

        lock_file.unlink(missing_ok=True)

    def _write_hashsums(
        self,
        fp_hash_types: dict[HashType, IO[str]],
        download_variant: DownloadFileCompressionVariant,
    ):
        for hashsum in download_variant.hashes.values():
            fp_hash_types[hashsum.type].write(
                f"{hashsum.hash}  {download_variant.path}{os.linesep}"
            )


def is_alternative_binary_path():
    return Path(sys.argv[0]).name == "apt-mirror2"


def get_config_file() -> Path:
    def get_prog() -> str | None:
        if Path(sys.argv[0]).name == "__main__.py":
            return f"{Path(sys.executable).name} -m apt_mirror"

        return None

    parser = argparse.ArgumentParser(prog=get_prog())

    default_configfile = Config.DEFAULT_CONFIGFILE
    if is_alternative_binary_path() and Path(Config.DEFAULT_CONFIGFILE2).exists():
        default_configfile = Config.DEFAULT_CONFIGFILE2

    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument(
        "configfile",
        help=f"Path to config file. Default {Config.DEFAULT_CONFIGFILE}",
        nargs="?",
        default=default_configfile,
    )

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    config_file = Path(args.configfile)
    if not config_file.is_file():
        LOG.error(f"invalid config file specified: {config_file}")
        sys.exit(1)

    return config_file


def main() -> int:
    config = Config(
        get_config_file(),
        Config.DEFAULT_BASE_PATH2
        if is_alternative_binary_path()
        else Config.DEFAULT_BASE_PATH,
    )

    # We should create working directories before using file logs
    config.create_working_directories()
    config.init_log_files()

    apt_mirror = APTMirror(config)
    try:
        if config.use_uvloop:
            if not UVLOOP_AVAILABLE:
                LOG.warning("uvloop is enabled but not available")

            return uvloop_run(apt_mirror.run())

        return asyncio.run(apt_mirror.run())
    except RuntimeError as ex:
        if apt_mirror.stopped:
            LOG.info("Stopped")
            return 0

        LOG.exception(ex)
        return 1
