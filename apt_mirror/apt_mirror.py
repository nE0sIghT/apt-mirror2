# SPDX-License-Identifer: GPL-3.0-or-later

import argparse
import asyncio
import itertools
import os
from errno import EWOULDBLOCK
from fcntl import LOCK_EX, LOCK_NB, flock
from pathlib import Path
from typing import Any, Awaitable, Iterable, Sequence

import uvloop

from .config import Config
from .download import Downloader, DownloadFile
from .logs import get_logger
from .repository import BaseRepository


class APTMirror:
    LOCK_FILE = "apt-mirror.lock"

    def __init__(self) -> None:
        self._log = get_logger(self)
        self._config = Config(self.get_config_file())
        self._lock_fd = None
        self._semaphore = asyncio.Semaphore(self._config.nthreads)
        self._download_semaphore = asyncio.Semaphore(self._config.nthreads)

    async def run(self):
        for variable in ("mirror_path", "base_path", "var_path"):
            path = Path(self._config[variable])
            path.mkdir(parents=True, exist_ok=True)

        self.lock()

        tasks: list[Awaitable[Any]] = []
        for repository in self._config.repositories.values():
            tasks.append(asyncio.create_task(self.mirror_repository(repository)))

        await asyncio.gather(*tasks)

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
                    *args, stdout=None, stderr=None
                )
                await process.wait()

                self._log.info(
                    "Post Mirror script has completed. See above output for any"
                    " possible errors."
                )

        self.unlock()

    async def mirror_repository(self, repository: BaseRepository):
        async with self._semaphore:
            self._log.info(f"Mirroring repository {repository}")

            downloader = await Downloader.for_url(
                repository.url,
                self._config.skel_path
                / repository.get_mirror_path(self._config.encode_tilde),
                self._download_semaphore,
            )

            release_files = await self.download_release_files(repository, downloader)

            # Download other metadata files
            metadata_files = await self.download_metadata_files(repository, downloader)
            if not metadata_files:
                self._log.error(
                    f"Unable to obtain metadata files for repository {repository}"
                )
                return metadata_files

            # Download remaining pool
            pool_files = await self.download_pool_files(repository, downloader)

            # Move skel to mirror
            await self.move_metadata(
                repository, itertools.chain(release_files, metadata_files)
            )

            if repository.clean:
                await self.clean_repository(
                    repository,
                    set(
                        itertools.chain.from_iterable(
                            file.get_all_paths()
                            for file in itertools.chain(
                                release_files, metadata_files, pool_files
                            )
                        )
                    ),
                    unlink=self._config.autoclean,
                )

    async def download_release_files(
        self, repository: BaseRepository, downloader: Downloader
    ) -> Sequence[DownloadFile]:
        # Download release files
        self._log.info(f"Downloading release files for repository {repository}")
        release_files = [
            DownloadFile.from_path(path) for path in repository.release_files
        ]
        downloader.add(*release_files)
        await downloader.download()

        return release_files

    async def download_metadata_files(
        self, repository: BaseRepository, downloader: Downloader
    ) -> Sequence[DownloadFile]:
        metadata_files = repository.get_metadata_files(
            self._config.skel_path,
            self._config.encode_tilde,
        )

        if not metadata_files:
            self._log.error(
                f"Unable to obtain metadata files for repository {repository}"
            )
            return metadata_files

        downloader.add(*metadata_files)

        self._log.info(
            f"Downloading {downloader.queue_files_count} metadata files for"
            f" repository {repository}. Total size is {downloader.queue_files_size}"
        )

        await downloader.download()

        return metadata_files

    async def download_pool_files(
        self, repository: BaseRepository, downloader: Downloader
    ) -> Iterable[DownloadFile]:
        downloader.set_target_path(
            self._config.mirror_path
            / repository.get_mirror_path(self._config.encode_tilde)
        )

        self._log.info(f"Processing metadata for repository {repository}")
        pool_files = repository.get_pool_files(
            self._config.skel_path,
            self._config.encode_tilde,
            downloader.get_missing_sources(),
        )

        downloader.add(*pool_files)

        self._log.info(
            f"Downloading {downloader.queue_files_count} pool files for repository"
            f" {repository}. Total size is {downloader.queue_files_size}"
        )

        await downloader.download()

        return pool_files

    async def move_metadata(
        self, repository: BaseRepository, metadata_files: Iterable[DownloadFile]
    ):
        self._log.info("Moving metadata")
        for file in metadata_files:
            mirror_path = repository.get_mirror_path(self._config.encode_tilde)
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

    async def clean_repository(
        self, repository: BaseRepository, needed_files: set[Path], unlink: bool
    ):
        def clean_file(path: Path) -> bool:
            nonlocal bytes_cleaned, files_count, fp, mirror_path

            if path.relative_to(mirror_path) in needed_files:
                return True

            files_count += 1
            bytes_cleaned += path.stat().st_size

            if fp:
                fp.write(f"rm -f '{path}'\n")
            else:
                path.unlink(missing_ok=True)

            return False

        def clean_folder(path: Path) -> bool:
            nonlocal bytes_cleaned, files_count, fp

            is_needed = False
            for file in path.glob("*"):
                if file.is_symlink():
                    is_needed = True
                    continue

                if file.is_file():
                    is_needed |= clean_file(file)

                if file.is_dir():
                    is_needed |= clean_folder(file)

            if not is_needed:
                files_count += 1

                if fp:
                    fp.write(f"rmdir '{path}\n")
                else:
                    path.rmdir()

            return is_needed

        files_count = 0
        bytes_cleaned = 0

        fp = None
        try:
            if not unlink:
                self._log.info(f"Creating clean script for repository {repository}")
                fp = open(
                    self._config.cleanscript.parent
                    / repository.get_clean_script_name(self._config.encode_tilde),
                    "wt",
                    encoding="utf-8",
                )
                fp.write(
                    "\n".join(
                        [
                            "#!/bin/bash",
                            "set -e",
                            "",
                            (
                                f"echo 'Removing {files_count} unnecessary files and"
                                " directories"
                                f" [{Downloader.format_size(bytes_cleaned)}] in"
                                f" repository {repository.url}...'"
                            ),
                            "",
                        ]
                        + [""]
                    )
                )
            else:
                self._log.info(f"Cleaning repository {repository}")

            mirror_path = self._config.mirror_path / repository.get_mirror_path(
                self._config.encode_tilde
            )

            clean_folder(
                self._config.mirror_path
                / repository.get_mirror_path(self._config.encode_tilde)
            )
        finally:
            if fp:
                fp.close()

        if not unlink:
            (
                self._config.cleanscript.parent
                / repository.get_clean_script_name(self._config.encode_tilde)
            ).chmod(0o750)

    def die(self, message: str, code: int = 1):
        self._log.error(message)
        exit(code)

    def get_config_file(self) -> Path:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "configfile",
            help=f"Path to config file. Default {Config.DEFAULT_CONFIGFILE}",
            nargs="?",
            default=Config.DEFAULT_CONFIGFILE,
        )

        args = parser.parse_args()

        config_file = Path(args.configfile)
        if not config_file.is_file():
            self.die("apt-mirror: invalid config file specified")

        return config_file

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


def main():
    uvloop.run(APTMirror().run())


if __name__ == "__main__":
    main()
