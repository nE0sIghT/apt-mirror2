# SPDX-License-Identifer: GPL-3.0-or-later

import bz2
import gzip
import itertools
import lzma
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Sequence

from debian.deb822 import Packages, Release, Sources

from .download import URL, DownloadFile, HashSum, HashType
from .logs import get_logger


class RepositoryType(Enum):
    BINARY = 0
    SOURCE = 1

    class UnknownTypeException(Exception):
        pass

    @staticmethod
    def from_string(type_string: str):
        if type_string == "deb":
            return RepositoryType.BINARY
        elif type_string == "deb-src":
            return RepositoryType.SOURCE

        raise RepositoryType.UnknownTypeException(
            f"Unknown repository type string: {type_string}"
        )


@dataclass
class BaseRepository(ABC):
    COMPRESSION_SUFFIXES = {
        ".xz": lzma.open,
        ".gz": gzip.open,
        ".bz2": bz2.open,
    }

    RELEASE_FILES = (
        "InRelease",
        "Release",
        "Release.gpg",
    )

    url: URL
    # Whether to mirror sources
    source: bool
    # Binary arches
    arches: list[str]

    clean: bool
    mirror_path: Path | None

    def __post_init__(self):
        self._log = get_logger(self)

    def get_mirror_path(self, encode_tilde: bool):
        if self.mirror_path:
            return self.mirror_path

        return self.url.as_filesystem_path(encode_tilde)

    def get_metadata_files(
        self, repository_root: Path, encode_tilde: bool
    ) -> Sequence[DownloadFile]:
        for release_file_relative_path in (self.inrelease_file, self.release_file):
            release_file = (
                repository_root
                / self.get_mirror_path(encode_tilde)
                / release_file_relative_path
            )

            if not release_file.exists():
                continue

            with open(release_file, "rt", encoding="utf-8") as fp:
                release = Release(fp)

            metadata_files: dict[Path, DownloadFile] = {}
            use_hash = release.get("Acquire-By-Hash") == "yes"

            for hash_type in HashType:
                for file in release.get(hash_type.value, []):
                    path = Path(file["name"])

                    if not self._metadata_file_allowed(path):
                        continue

                    hash_sum = HashSum(type=hash_type, hash=file[hash_type.value])

                    if path in metadata_files:
                        metadata_files[path].hashes[hash_sum.type] = hash_sum
                    else:
                        metadata_files[path] = DownloadFile(
                            release_file_relative_path.parent / path,
                            size=int(file["size"]),
                            hashes={
                                hash_sum.type: hash_sum,
                            },
                            use_by_hash=use_hash,
                        )

            return list(metadata_files.values())

        return []

    def _try_unpack(self, file: Path):
        for suffix, open_function in self.COMPRESSION_SUFFIXES.items():
            compressed_file = file.with_name(f"{file.name}{suffix}")
            if not compressed_file.exists():
                continue

            with open_function(compressed_file, "rb") as source_fp:
                with open(file, "wb") as target_fp:
                    shutil.copyfileobj(source_fp, target_fp)
                    shutil.copystat(compressed_file, file)

                    return True

        return False

    def _get_sources_files_field(self, hash_type: HashType):
        if hash_type == HashType.MD5:
            return "Files"

        return f"Checksum-{hash_type.value.capitalize()}"

    def get_pool_files(
        self, repository_root: Path, encode_tilde: bool
    ) -> Sequence[DownloadFile]:
        pool_files: dict[Path, DownloadFile] = {}

        if self.source:
            for sources_file_relative_path in self.sources_files:
                sources_file = (
                    repository_root
                    / self.get_mirror_path(encode_tilde)
                    / sources_file_relative_path
                )

                if not self._try_unpack(sources_file):
                    self._log.info(f"No index file {sources_file}. Skipping")
                    continue

                with open(sources_file, "rt", encoding="utf-8") as fp:
                    for sources in Sources.iter_paragraphs(fp):
                        directory = Path(sources["Directory"])

                        for hash_type in HashType:
                            for pool_file in sources.get(
                                self._get_sources_files_field(hash_type), []
                            ):
                                path = directory / pool_file["name"]

                                hash_sum = HashSum(
                                    type=hash_type, hash=pool_file[hash_type.value]
                                )

                                if path in pool_files:
                                    pool_files[path].hashes[hash_sum.type] = hash_sum
                                else:
                                    pool_files[path] = DownloadFile(
                                        path,
                                        size=int(pool_file["size"]),
                                        hashes={
                                            hash_sum.type: hash_sum,
                                        },
                                        use_by_hash=False,
                                        check_size=True,
                                    )

        if self.arches:
            for packages_file_relative_path in self.packages_files:
                packages_file = (
                    repository_root
                    / self.get_mirror_path(encode_tilde)
                    / packages_file_relative_path
                )

                if not self._try_unpack(packages_file):
                    # This is optional
                    if "binary-all" not in str(packages_file):
                        self._log.info(f"No index file {packages_file}. Skipping")
                    continue

                with open(packages_file, "rt", encoding="utf-8") as fp:
                    for packages in Packages.iter_paragraphs(fp):
                        path = Path(packages["Filename"])
                        size = int(packages["Size"])

                        pool_files[path] = DownloadFile(
                            path,
                            size=size,
                            hashes={},
                            use_by_hash=False,
                            check_size=True,
                        )

                        for hash_type in HashType:
                            if not packages.get(hash_type.value):
                                continue

                            pool_files[path].hashes[hash_type] = HashSum(
                                type=hash_type, hash=packages[hash_type.value]
                            )

        return list(pool_files.values())

    @abstractmethod
    def _metadata_file_allowed(self, file_path: Path) -> bool: ...

    @property
    @abstractmethod
    def release_files(self) -> Sequence[Path]: ...

    @property
    @abstractmethod
    def inrelease_file(self) -> Path: ...

    @property
    @abstractmethod
    def release_file(self) -> Path: ...

    @property
    @abstractmethod
    def sources_files(self) -> Sequence[Path]: ...

    @property
    @abstractmethod
    def packages_files(self) -> Sequence[Path]: ...

    def __str__(self) -> str:
        return (
            f"{self.url}, arches: {self.arches}, source: {self.source}, mirror_path:"
            f" {self.mirror_path}"
        )


@dataclass
class Repository(BaseRepository):
    DISTS = Path("dists")

    codename: str
    components: list[str]

    def _metadata_file_allowed(self, file_path: Path) -> bool:
        source_files = (
            "Sources",
            "Contents-source",
        )

        if self.source and (
            any(
                file_path.name.endswith(f"{name}{suffix}")
                for name in source_files
                for suffix in self.COMPRESSION_SUFFIXES
            )
        ):
            return True

        if self.arches:
            for arch in self.arches:
                for suffix in self.COMPRESSION_SUFFIXES:
                    if any(
                        str(file_path) == name
                        for name in (
                            f"Contents-{arch}{suffix}",
                            f"Contents-udeb-{arch}{suffix}",
                        )
                    ):
                        return True

            if any(
                str(file_path).startswith(component) for component in self.components
            ):
                for arch in self.arches:
                    if str(file_path).endswith(f"binary-{arch}/Release"):
                        return True

                    for suffix in self.COMPRESSION_SUFFIXES:
                        if any(
                            str(file_path).endswith(name)
                            for name in (
                                f"Contents-{arch}{suffix}",
                                f"Contents-udeb-{arch}{suffix}",
                                f"binary-{arch}/Packages{suffix}",
                                f"binary-{arch}/Release",
                                f"cnf/Commands-{arch}{suffix}",
                                f"dep11/Components-{arch}.yml{suffix}",
                            )
                        ) or (
                            any(
                                f"/{part}/" in str(file_path)
                                for part in ("dep11", "i18n")
                            )
                            and any(
                                file_path.name.startswith(prefix)
                                and file_path.suffix == suffix
                                for prefix in ("icons-", "Translation-")
                            )
                        ):
                            return True

        return False

    @property
    def release_files(self) -> Sequence[Path]:
        return [self.DISTS / self.codename / file for file in self.RELEASE_FILES]

    @property
    def inrelease_file(self) -> Path:
        return self.DISTS / self.codename / "InRelease"

    @property
    def release_file(self) -> Path:
        return self.DISTS / self.codename / "Release"

    @property
    def sources_files(self) -> Sequence[Path]:
        if not self.source:
            return []

        return [
            self.DISTS / self.codename / component / "source" / "Sources"
            for component in self.components
        ]

    @property
    def packages_files(self) -> Sequence[Path]:
        if not self.arches:
            return []

        return [
            path
            for path in itertools.chain.from_iterable(
                itertools.chain(
                    (
                        self.DISTS
                        / self.codename
                        / component
                        / f"binary-{arch}"
                        / "Packages"
                        for arch in self.arches
                    ),
                    [
                        self.DISTS
                        / self.codename
                        / component
                        / "binary-all"
                        / "Packages"
                    ],
                )
                for component in self.components
            )
        ]


@dataclass
class FlatRepository(BaseRepository):
    directory: str

    def _metadata_file_allowed(self, file_path: Path) -> bool:
        if self.source and (
            any(
                str(file_path) == f"Sources{suffix}"
                for suffix in self.COMPRESSION_SUFFIXES
            )
        ):
            return True

        if self.arches and (
            any(
                str(file_path) == f"Packages{suffix}"
                for suffix in self.COMPRESSION_SUFFIXES
            )
        ):
            return True

        return False

    @property
    def release_files(self) -> Sequence[Path]:
        return [Path(file) for file in self.RELEASE_FILES]

    @property
    def inrelease_file(self) -> Path:
        return Path("InRelease")

    @property
    def release_file(self) -> Path:
        return Path("Release")

    @property
    def sources_files(self) -> Sequence[Path]:
        if not self.source:
            return []

        return [Path(self.directory) / "Sources"]

    @property
    def packages_files(self) -> Sequence[Path]:
        if not self.arches:
            return []

        return [Path(self.directory) / "Packages"]
