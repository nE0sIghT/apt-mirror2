# SPDX-License-Identifer: GPL-3.0-or-later

import argparse
import asyncio
import itertools
import os
import signal
from errno import EWOULDBLOCK
from fcntl import LOCK_EX, LOCK_NB, flock
from pathlib import Path
from typing import IO, Awaitable, Iterable, Sequence

from aiolimiter import AsyncLimiter

from .config import Config
from .download import Downloader, DownloadFile, DownloadFileCompressionVariant
from .logs import get_logger
from .repository import BaseRepository
from .version import __version__

LOG = get_logger(__package__)


class PathCleaner:
    def __init__(self, root_path: Path, keep_files: set[Path]) -> None:
        self._log = get_logger(self)

        self._root_path = root_path

        self._bytes_cleaned = 0
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
        if path.relative_to(self._root_path) in self._keep_files:
            return True

        self._bytes_cleaned += path.stat().st_size
        self._files_queue.append(path)

        return False

    @property
    def bytes_cleaned(self):
        return self._bytes_cleaned

    @property
    def files_count(self):
        return len(self._files_queue)

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
                    (
                        f"echo 'Removing {len(self._files_queue)}"
                        f" [{Downloader.format_size(self._bytes_cleaned)}]"
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

    def clean(self):
        for file in self._files_queue:
            file.unlink(missing_ok=True)

        for folder in self._folders_queue:
            folder.rmdir()

        self._log.info(
            "Removed"
            f" {len(self._files_queue)} [{Downloader.format_size(self._bytes_cleaned)}]"
            f" unnecessary files and {len(self._folders_queue)} unnecessary folders"
        )


class RepositoryMirror:
    def __init__(
        self,
        repository: BaseRepository,
        config: Config,
        semaphore: asyncio.Semaphore,
        download_semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter | None,
    ) -> None:
        self._log = get_logger(self)
        self._error = False

        self._repository = repository

        self._config = config
        self._download_semaphore = download_semaphore
        self._semaphore = semaphore
        self._rate_limiter = rate_limiter

        self._downloader = Downloader.for_url(
            url=self._repository.url,
            target_root_path=self._config.skel_path
            / self._repository.get_mirror_path(self._config.encode_tilde),
            proxy=self._config.proxy,
            user_agent=self._config.user_agent,
            semaphore=self._download_semaphore,
            rate_limiter=self._rate_limiter,
            verify_ca_certificate=self._config.verify_ca_certificate,
            client_certificate=self._config.client_certificate,
            client_private_key=self._config.client_private_key,
        )

    async def mirror(self) -> bool:
        """Start repository mirror process

        Returns:
            bool: True if mirror was successful, False otherwise
        """
        async with self._semaphore:
            self._log.info(f"Mirroring repository {self._repository}")

            await self.download_release_files()

            # Download other metadata files
            metadata_files = await self.download_metadata_files()
            if not metadata_files:
                self._log.error(
                    f"Unable to obtain metadata files for repository {self._repository}"
                )
                return False

            downloaded_metadata_files = self._downloader.get_downloaded_files()

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
            await self.move_metadata(downloaded_metadata_files)

            if self._repository.clean:
                await self.clean_repository(
                    needed_files=set(
                        itertools.chain.from_iterable(
                            v.get_all_paths()
                            for v in self._downloader.get_downloaded_files()
                        )
                    )
                    - self._downloader.get_missing_sources(),
                    unlink=self._config.autoclean,
                )

        return not self._error

    async def download_release_files(self) -> Sequence[DownloadFile]:
        # Download release files
        self._log.info(f"Downloading release files for repository {self._repository}")
        release_files = [
            DownloadFile.from_path(path) for path in self._repository.release_files
        ]
        self._downloader.add(*release_files)
        await self._downloader.download()

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
            f" {self._downloader.queue_files_size}"
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
        pool_files = self._repository.get_pool_files(
            self._config.skel_path,
            self._config.encode_tilde,
            self._downloader.get_missing_sources(),
        )

        self._downloader.add(*pool_files)

        self._log.info(
            f"Downloading {self._downloader.queue_files_count} pool files for"
            f" repository {self._repository}. Total size is"
            f" {self._downloader.queue_files_size}"
        )

        await self._downloader.download()

        if self._downloader.has_errors() or self._downloader.has_missing():
            self._error = True

        return pool_files

    async def move_metadata(
        self,
        metadata_files: Iterable[DownloadFileCompressionVariant],
    ):
        self._log.info("Moving metadata")
        for file in metadata_files:
            mirror_path = self._repository.get_mirror_path(self._config.encode_tilde)
            file_relative_path = mirror_path / file.path
            file_skel_path = self._config.skel_path / file_relative_path

            if file_skel_path.exists():
                Downloader.link_or_copy(
                    file_skel_path,
                    *[
                        self._config.mirror_path / mirror_path / f
                        for f in file.get_all_paths()
                    ],
                )

    async def clean_repository(self, needed_files: set[Path], unlink: bool):
        cleaner = PathCleaner(
            self._config.mirror_path
            / self._repository.get_mirror_path(self._config.encode_tilde),
            needed_files | self._repository.skip_clean,
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
        )

        cleaner.clean()


class APTMirror:
    LOCK_FILE = "apt-mirror.lock"

    def __init__(self, config: Config) -> None:
        self.stopped = False

        self._log = get_logger(self)
        self._config = config
        self._lock_fd = None

        self._semaphore = asyncio.Semaphore(self._config.nthreads)
        self._download_semaphore = asyncio.Semaphore(self._config.nthreads)

        self._error: bool = False

        self._rate_limiter = None
        if self._config.limit_rate:
            self._rate_limiter = AsyncLimiter(self._config.limit_rate * 60, 60)

    def on_stop(self):
        self.stopped = True
        asyncio.get_running_loop().stop()

    async def run(self) -> int:
        signal.signal(signal.SIGTERM, lambda _, __: self.on_stop())

        if not self._config.repositories:
            self._log.error("No repositories are found in the configuration")
            return 2

        for variable in ("mirror_path", "base_path", "var_path"):
            path = Path(self._config[variable])
            path.mkdir(parents=True, exist_ok=True)

        self.lock()

        tasks: list[Awaitable[bool]] = []
        for repository in self._config.repositories.values():
            mirror = RepositoryMirror(
                repository,
                self._config,
                self._semaphore,
                self._download_semaphore,
                self._rate_limiter,
            )
            tasks.append(asyncio.create_task(mirror.mirror()))

        self._error = not all(await asyncio.gather(*tasks))

        if not self._config.autoclean and any(
            r.clean for r in self._config.repositories.values()
        ):
            self._log.info(f"Writing clean script {self._config.cleanscript}")
            with open(self._config.cleanscript, "wt", encoding="utf-8") as fp:
                fp.write(
                    "\n".join([
                        "#!/bin/sh",
                        "set -e",
                        "",
                    ])
                )

                for repository in self._config.repositories.values():
                    if not repository.clean:
                        continue

                    clean_script = (
                        self._config.cleanscript.parent
                        / repository.get_clean_script_name(self._config.encode_tilde)
                    )
                    fp.write(f"sh '{clean_script}'\n")

            self._config.cleanscript.chmod(0o750)

        if self._config.run_postmirror:
            if not self._config.postmirror_script.is_file():
                self._log.error(
                    "Post Mirror script is missing: {self._config.postmirror_script}"
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

        self.unlock()

        if self._error:
            self._log.error(
                "Some files were not downloaded. Please check logs above for details."
            )
            return 1

        return 0

    def die(self, message: str, code: int = 1):
        self._log.error(message)
        exit(code)

    def get_lock_file(self):
        return self._config.var_path / self.LOCK_FILE

    def lock(self):
        lock_file = self.get_lock_file()
        self._lock_fd = open(lock_file, "wb")
        try:
            flock(self._lock_fd, LOCK_EX | LOCK_NB)
        except OSError as ex:
            if ex.errno == EWOULDBLOCK:
                self.die("apt-mirror is already running, exiting")

            self.die(
                f"Unable to obtain lock on {lock_file}: error {ex.errno}:"
                f" {os.strerror(ex.errno)}"
            )

    def unlock(self):
        if self._lock_fd:
            self._lock_fd.close()
            self._lock_fd = None

            self.get_lock_file().unlink(missing_ok=True)


def get_config_file() -> Path:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument(
        "configfile",
        help=f"Path to config file. Default {Config.DEFAULT_CONFIGFILE}",
        nargs="?",
        default=Config.DEFAULT_CONFIGFILE,
    )

    args = parser.parse_args()

    if args.version:
        print(__version__)
        exit(0)

    config_file = Path(args.configfile)
    if not config_file.is_file():
        LOG.error("invalid config file specified")
        exit(1)

    return config_file


def main() -> int:
    config = Config(get_config_file())

    asyncio_loop = asyncio
    if config.use_uvloop:
        try:
            import uvloop  # pylint: disable=C0415

            asyncio_loop = uvloop
        except ModuleNotFoundError:
            LOG.warning("uvloop is enabled but not available")

    apt_mirror = APTMirror(config)
    try:
        return asyncio_loop.run(apt_mirror.run())
    except RuntimeError as ex:
        if apt_mirror.stopped:
            LOG.info("Stopped")
            return 0

        LOG.exception(ex)
        return 1


if __name__ == "__main__":
    exit(main())
