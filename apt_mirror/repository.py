# SPDX-License-Identifer: GPL-3.0-or-later

import bz2
import gzip
import itertools
import lzma
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from mmap import MADV_SEQUENTIAL, MAP_POPULATE, MAP_PRIVATE, mmap
from pathlib import Path
from typing import IO, Iterable, Sequence

from debian.deb822 import Release

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
class PackageFile:
    path: Path
    size: int
    hashes: dict[HashType, HashSum]

    def to_download_file(self, directory: str):
        return DownloadFile(
            path=Path(directory) / self.path,
            size=self.size,
            hashes=self.hashes,
            use_by_hash=False,
            check_size=True,
        )


class IndexFileParser(ABC):
    def __init__(self, repository_path: Path, index_files: set[Path]) -> None:
        super().__init__()

        self._log = get_logger(self)
        self._repository_path = repository_path
        self._index_files = index_files
        self._pool_files: dict[Path, DownloadFile] = {}

    def parse(self) -> set[DownloadFile]:
        for index_file_relative_path in self._index_files:
            index_file = self._repository_path / index_file_relative_path

            if not self._unpack_index(index_file):
                if "binary-all" not in str(index_file):
                    self._log.warning(
                        f"Unable to unpack index file {index_file}. Skipping"
                    )
                continue

            index_file_size = index_file.stat().st_size
            if index_file_size < 1:
                continue

            with open(index_file, "rb") as fp:
                mfp = fp
                if index_file_size > 1 * 1024 * 1024:
                    mfp = mmap(
                        fp.fileno(),
                        length=0,
                        flags=MAP_PRIVATE | MAP_POPULATE,
                    )

                try:
                    if isinstance(mfp, mmap):
                        mfp.madvise(MADV_SEQUENTIAL)

                    self._do_parse_index(mfp)
                finally:
                    if isinstance(mfp, mmap):
                        mfp.close()

        return set(self._pool_files.values())

    def _unpack_index(self, file: Path) -> bool:
        for suffix, open_function in BaseRepository.COMPRESSION_SUFFIXES.items():
            compressed_file = file.with_name(f"{file.name}{suffix}")
            if not compressed_file.exists():
                continue

            with open_function(compressed_file, "rb") as source_fp:
                with open(file, "wb") as target_fp:
                    shutil.copyfileobj(source_fp, target_fp)
                    shutil.copystat(compressed_file, file)

                    return True

        return False

    @abstractmethod
    def _do_parse_index(self, fp: IO[bytes] | mmap): ...


class SourcesParser(IndexFileParser):
    def __init__(self, repository_path: Path, index_files: set[Path]) -> None:
        super().__init__(repository_path, index_files)
        self._reset_block_parser()

    # https://github.com/pylint-dev/pylint/issues/5214
    def _reset_block_parser(self):
        self._directory: str | None = None
        self._hash_type = None
        self._package_files: dict[Path, PackageFile] = {}

    def _do_parse_index(self, fp: IO[bytes] | mmap):
        self._reset_block_parser()

        for bytes_line in iter(fp.readline, b""):
            if bytes_line[0] == ord(" "):
                if not self._hash_type:
                    continue

                try:
                    hashsum, _size, filename = (
                        bytes_line.decode().strip().split(maxsplit=2)
                    )
                except ValueError:
                    continue

                if " " in filename:
                    continue

                file_path = Path(filename)
                self._package_files.setdefault(
                    file_path,
                    PackageFile(path=file_path, size=int(_size), hashes={}),
                ).hashes[self._hash_type] = HashSum(type=self._hash_type, hash=hashsum)
            elif bytes_line[0] != ord("\n"):
                match bytes_line:
                    case line if line.startswith(b"Directory:"):
                        # https://github.com/pylint-dev/pylint/issues/5214
                        _, self._directory = (  # pylint: disable=W0201
                            line.decode().strip().split()
                        )
                    case line if line.startswith(b"Files:"):
                        self._hash_type = HashType.MD5  # pylint: disable=W0201
                        continue
                    case line if line.startswith(b"Checksums-"):
                        match line[len(b"Checksums-") : -1]:
                            case b"Sha1:":
                                self._hash_type = HashType.SHA1  # pylint: disable=W0201
                            case b"Sha256:":
                                self._hash_type = (  # pylint: disable=W0201
                                    HashType.SHA256
                                )
                            case b"Sha512:":
                                self._hash_type = (  # pylint: disable=W0201
                                    HashType.SHA512
                                )
                            case _:
                                self._hash_type = None  # pylint: disable=W0201

                        continue
                    case _:
                        self._hash_type = None  # pylint: disable=W0201
                        continue
            else:
                if not self._directory:
                    continue

                for package_file in self._package_files.values():
                    download_file = package_file.to_download_file(self._directory)
                    self._pool_files[download_file.path] = download_file

                self._reset_block_parser()


class PackagesParser(IndexFileParser):
    def __init__(self, repository_path: Path, index_files: set[Path]) -> None:
        super().__init__(repository_path, index_files)
        self._reset_block_parser()

    def _reset_block_parser(self):
        self._file_path = None
        self._size = 0
        self._hashes: dict[HashType, HashSum] = {}

    def _do_parse_index(self, fp: IO[bytes] | mmap):
        for bytes_line in iter(fp.readline, b""):
            if bytes_line[0] != ord("\n"):
                match bytes_line:
                    case line if line.startswith(b"Filename:"):
                        self._file_path = Path(  # pylint: disable=W0201
                            self._get_line_value(line)
                        )
                    case line if line.startswith(b"Size:"):
                        self._size = int(  # pylint: disable=W0201
                            self._get_line_value(line)
                        )
                    case line if line.startswith(b"%s:" % HashType.MD5.value.encode()):
                        self._hashes[HashType.MD5] = HashSum(
                            type=HashType.MD5, hash=self._get_line_value(line)
                        )
                    case line if line.startswith(b"%s:" % HashType.SHA1.value.encode()):
                        self._hashes[HashType.MD5] = HashSum(
                            type=HashType.SHA1, hash=self._get_line_value(line)
                        )
                    case line if line.startswith(
                        b"%s:" % HashType.SHA256.value.encode()
                    ):
                        self._hashes[HashType.SHA256] = HashSum(
                            type=HashType.SHA256, hash=self._get_line_value(line)
                        )
                    case line if line.startswith(
                        b"%s:" % HashType.SHA512.value.encode()
                    ):
                        self._hashes[HashType.SHA512] = HashSum(
                            type=HashType.SHA512, hash=self._get_line_value(line)
                        )
                    case _:
                        self._hash_type = None  # pylint: disable=W0201
                        continue
            else:
                if not self._file_path or not self._size:
                    continue

                self._pool_files[self._file_path] = DownloadFile(
                    path=self._file_path,
                    size=self._size,
                    hashes=self._hashes,
                    use_by_hash=False,
                    check_size=True,
                )

                self._reset_block_parser()

    def _get_line_value(self, line: bytes):
        return line.decode().strip().split(":", maxsplit=1)[1].strip()


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

    def get_clean_script_name(self, encode_tilde: bool):
        path = Path(str(self.get_mirror_path(encode_tilde)).replace("/", "_"))
        return path.with_name(f"{path.name}.sh")

    def get_metadata_files(
        self, repository_root: Path, encode_tilde: bool, missing_sources: set[Path]
    ) -> Sequence[DownloadFile]:
        for release_file_relative_path in (self.inrelease_file, self.release_file):
            if release_file_relative_path in missing_sources:
                continue

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
        self, repository_root: Path, encode_tilde: bool, missing_sources: set[Path]
    ) -> Iterable[DownloadFile]:
        pool_files: set[DownloadFile] = set()

        if self.source:
            pool_files.update(
                SourcesParser(
                    repository_root / self.get_mirror_path(encode_tilde),
                    set(self.sources_files) - missing_sources,
                ).parse()
            )

        if self.arches:
            pool_files.update(
                PackagesParser(
                    repository_root / self.get_mirror_path(encode_tilde),
                    set(self.packages_files) - missing_sources,
                ).parse()
            )

        return pool_files

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
