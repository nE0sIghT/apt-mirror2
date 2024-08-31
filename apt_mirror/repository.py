# SPDX-License-Identifer: GPL-3.0-or-later

import bz2
import gzip
import itertools
import lzma
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from mmap import MADV_SEQUENTIAL, MAP_PRIVATE, mmap
from pathlib import Path
from typing import IO, Any, Iterable, Sequence

from debian.deb822 import Release

from .download import URL, DownloadFile, FileCompression, HashSum, HashType
from .filter import PackageFilter
from .logs import LoggerFactory

# https://github.com/pypy/pypy/issues/4991
# TODO: replace again with `from mmap import MAP_POPULATE`
MAP_POPULATE = 0x008000


def should_ignore_errors(ignored_paths: set[str], path: Path):
    return any(path.is_relative_to(ignored_path) for ignored_path in ignored_paths)


class InvalidReleaseFilesException(RuntimeError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class PackageFile:
    path: Path
    size: int
    hashes: dict[HashType, HashSum]

    def to_download_file(self, directory: str):
        download_file = DownloadFile.from_path(
            path=Path(directory) / self.path, check_size=True
        )
        for hash_type, hashsum in self.hashes.items():
            download_file.add_compression_variant(
                Path(directory) / self.path,
                size=self.size,
                hash_type=hash_type,
                hash_sum=hashsum,
                use_by_hash=False,
            )

        return download_file


class IndexFileParser(ABC):
    def __init__(
        self,
        repository_path: Path,
        index_files: set[Path],
        ignore_errors: set[str],
        logger_id: Any | None = None,
    ) -> None:
        super().__init__()

        self._log = LoggerFactory.get_logger(self, logger_id=logger_id)
        self._repository_path = repository_path
        self._index_files = index_files
        self._ignore_errors = ignore_errors
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
                    mfp.madvise(MADV_SEQUENTIAL)

                try:
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

            try:
                with open_function(compressed_file, "rb") as source_fp:
                    with open(file, "wb") as target_fp:
                        shutil.copyfileobj(source_fp, target_fp)
                        shutil.copystat(compressed_file, file)

                        return True
            except (lzma.LZMAError, OSError):
                return False

        return file.exists()

    def _should_ignore_errors(self, path: Path):
        return should_ignore_errors(self._ignore_errors, path)

    @abstractmethod
    def _do_parse_index(self, fp: IO[bytes] | mmap): ...


class SourcesParser(IndexFileParser):
    def __init__(
        self,
        repository_path: Path,
        index_files: set[Path],
        ignore_errors: set[str],
        package_filter: PackageFilter,
        logger_id: Any | None = None,
    ) -> None:
        super().__init__(
            repository_path, index_files, ignore_errors, logger_id=logger_id
        )

        self._package_filter = package_filter

        self._reset_block_parser()

    # https://github.com/pylint-dev/pylint/issues/5214
    def _reset_block_parser(self):
        self._package: str | None = None
        self._directory: str | None = None
        self._hash_type = None
        self._package_files: dict[Path, PackageFile] = {}

    def _do_parse_index(self, fp: IO[bytes] | mmap):
        self._reset_block_parser()

        for bytes_line in itertools.chain(iter(fp.readline, b""), (b"\n",)):
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
                    case line if line.startswith(b"Package:"):
                        _, self._package = (  # pylint: disable=W0201
                            line.decode().strip().split()
                        )
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
                if not self._package or not self._directory:
                    self._reset_block_parser()
                    continue

                if not self._package_filter.package_allowed(self._package):
                    self._reset_block_parser()
                    continue

                for package_file in self._package_files.values():
                    download_file = package_file.to_download_file(self._directory)
                    download_file.ignore_errors = self._should_ignore_errors(
                        download_file.path
                    )
                    self._pool_files[download_file.path] = download_file

                self._reset_block_parser()


class PackagesParser(IndexFileParser):
    def __init__(
        self,
        repository_path: Path,
        index_files: set[Path],
        ignore_errors: set[str],
        package_filter: PackageFilter,
        logger_id: Any | None = None,
    ) -> None:
        super().__init__(
            repository_path, index_files, ignore_errors, logger_id=logger_id
        )

        self._package_filter = package_filter

        self._reset_block_parser()

    def _reset_block_parser(self):
        self._package = None
        self._source = None
        self._file_path = None
        self._size = 0
        self._hashes: dict[HashType, HashSum] = {}

    def _do_parse_index(self, fp: IO[bytes] | mmap):
        for bytes_line in itertools.chain(iter(fp.readline, b""), (b"\n",)):
            if bytes_line[0] != ord("\n"):
                match bytes_line:
                    case line if line.startswith(b"Package:"):
                        self._package = self._get_line_value(  # pylint: disable=W0201
                            line
                        )
                    case line if line.startswith(b"Source:"):
                        self._source = self._get_line_value(  # pylint: disable=W0201
                            line
                        ).split()[0]
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
                if not self._package or not self._file_path or not self._size:
                    self._reset_block_parser()
                    continue

                source_name = self._source if self._source else self._package

                if not self._package_filter.package_allowed(source_name, self._package):
                    self._reset_block_parser()
                    continue

                download_file = DownloadFile.from_path(self._file_path, check_size=True)
                download_file.ignore_errors = self._should_ignore_errors(
                    download_file.path
                )
                for hash_type, hashsum in self._hashes.items():
                    download_file.add_compression_variant(
                        path=self._file_path,
                        size=self._size,
                        hash_type=hash_type,
                        hash_sum=hashsum,
                        use_by_hash=False,
                    )

                self._pool_files[self._file_path] = download_file

                self._reset_block_parser()

    def _get_line_value(self, line: bytes):
        return line.decode().strip().split(":", maxsplit=1)[1].strip()


class ByHash(Enum):
    YES = "yes"
    NO = "no"
    FORCE = "force"

    @staticmethod
    def default():
        return ByHash.YES


@dataclass
class BaseRepositoryMetadata(ABC):
    by_hash: ByHash

    @abstractmethod
    def as_path(self) -> Path: ...

    def as_string(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return hash(str(self))


@dataclass(eq=False)
class Codename(BaseRepositoryMetadata):
    @dataclass
    class Component:
        name: str
        mirror_source: bool
        arches: list[str]

    codename: str
    components: dict[str, Component]

    def as_path(self) -> Path:
        return Path("dists") / self.codename

    def should_mirror_source(self):
        return any(c.mirror_source for c in self.components.values())

    def should_mirror_binaries(self):
        return any(c.arches for c in self.components.values())

    def __str__(self) -> str:
        return self.codename


@dataclass(eq=False)
class FlatDirectory(BaseRepositoryMetadata):
    directory: Path
    mirror_source: bool
    mirror_binaries: bool

    def as_path(self) -> Path:
        return self.directory

    def __str__(self) -> str:
        return str(self.directory)


@dataclass
class BaseRepository(ABC):
    COMPRESSION_SUFFIXES = {
        FileCompression.XZ.file_extension: lzma.open,
        FileCompression.GZ.file_extension: gzip.open,
        FileCompression.BZ2.file_extension: bz2.open,
    }

    ALL_INDEX_SUFFIXES = list(COMPRESSION_SUFFIXES.keys()) + [""]

    RELEASE_FILES = (
        "InRelease",
        "Release",
        "Release.gpg",
    )

    url: URL

    clean: bool
    skip_clean: set[Path]
    mirror_path: Path | None
    ignore_errors: set[str]

    def __post_init__(self):
        self._log = LoggerFactory.get_logger(self)

        self.package_filter = PackageFilter()

    def get_mirror_path(self, encode_tilde: bool):
        if self.mirror_path:
            return self.mirror_path

        return self.url.as_filesystem_path(encode_tilde)

    def as_filename(self, encode_tilde: bool) -> Path:
        return Path(
            str(self.get_mirror_path(encode_tilde=encode_tilde)).replace(os.sep, "_")
        )

    def get_clean_script_name(self, encode_tilde: bool):
        path = Path(str(self.get_mirror_path(encode_tilde)).replace("/", "_"))
        return path.with_name(f"{path.name}.sh")

    def get_metadata_files(
        self, repository_root: Path, encode_tilde: bool, missing_sources: set[Path]
    ) -> Iterable[DownloadFile]:
        metadata_files: set[DownloadFile] = set()

        for (
            metadata,
            metadata_release_files,
        ) in self.release_files_per_metadata.items():
            codename_metadata_files: dict[Path, DownloadFile] = {}

            for release_file_relative_path in metadata_release_files:
                if release_file_relative_path.suffix == ".gpg":
                    continue

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

                use_hash = release.get("Acquire-By-Hash") == "yes"
                if use_hash:
                    if self.get_by_hash_policy(metadata) == ByHash.NO:
                        use_hash = False
                elif self.get_by_hash_policy(metadata) == ByHash.FORCE:
                    use_hash = True

                for hash_type in HashType:
                    for file in release.get(hash_type.value, []):
                        path = Path(file["name"])
                        try:
                            size = int(file["size"])
                        except ValueError:
                            size = 0

                        if size <= 0:
                            continue

                        # Ignore release files in release files
                        if file["name"] in self.RELEASE_FILES:
                            continue

                        if not self._metadata_file_allowed(metadata, path):
                            continue

                        hash_sum = HashSum(type=hash_type, hash=file[hash_type.value])

                        repository_path = release_file_relative_path.parent / path
                        uncompressed_path = DownloadFile.uncompressed_path(path)
                        if uncompressed_path in codename_metadata_files:
                            codename_metadata_files[
                                uncompressed_path
                            ].add_compression_variant(
                                path=repository_path,
                                size=size,
                                hash_type=hash_type,
                                hash_sum=hash_sum,
                                use_by_hash=use_hash,
                            )
                        else:
                            codename_metadata_files[uncompressed_path] = (
                                DownloadFile.from_hashed_path(
                                    repository_path,
                                    size=size,
                                    hash_type=hash_type,
                                    hash_sum=hash_sum,
                                    use_by_hash=use_hash,
                                )
                            )

                        codename_metadata_files[uncompressed_path].ignore_errors = (
                            should_ignore_errors(self.ignore_errors, uncompressed_path)
                        )

            if not codename_metadata_files:
                self._log.warning(f"No metadata files found for codename {metadata}")

            metadata_files.update(codename_metadata_files.values())

        return metadata_files

    def _get_sources_files_field(self, hash_type: HashType):
        if hash_type == HashType.MD5:
            return "Files"

        return f"Checksum-{hash_type.value.capitalize()}"

    def get_pool_files(
        self, repository_root: Path, encode_tilde: bool, missing_sources: set[Path]
    ) -> Iterable[DownloadFile]:
        pool_files: set[DownloadFile] = set()

        if self.is_source_enabled:
            pool_files.update(
                SourcesParser(
                    repository_root / self.get_mirror_path(encode_tilde),
                    set(self.sources_files) - missing_sources,
                    ignore_errors=self.ignore_errors,
                    package_filter=self.package_filter,
                    logger_id=self.url,
                ).parse()
            )

        if self.is_binaries_enabled:
            pool_files.update(
                PackagesParser(
                    repository_root / self.get_mirror_path(encode_tilde),
                    set(self.packages_files) - missing_sources,
                    ignore_errors=self.ignore_errors,
                    package_filter=self.package_filter,
                    logger_id=self.url,
                ).parse()
            )

        return pool_files

    def validate_release_files(self, repository_root: Path, encode_tilde: bool):
        release_files_exists = False

        for _, metadata_release_files in self.release_files_per_metadata.items():
            metadata_sizes: dict[str, list[tuple[int, Path]]] = {}
            metadata_hashes: dict[str, dict[HashType, list[tuple[str, Path]]]] = {}

            for release_file_relative_path in metadata_release_files:
                if release_file_relative_path.suffix == ".gpg":
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

                release_files_exists = True
                for hash_type in HashType:
                    for file in release.get(hash_type.value, []):
                        try:
                            size = int(file["size"])
                        except ValueError:
                            size = 0

                        if size <= 0:
                            continue

                        # Ignore release files in release files
                        if file["name"] in self.RELEASE_FILES:
                            continue

                        path = file["name"]
                        hash_sum = file[hash_type.value]

                        if any(size != s[0] for s in metadata_sizes.get(path, [])):
                            raise InvalidReleaseFilesException(
                                f"Size of file {path} in release file"
                                f" {release_file_relative_path} differs from size in"
                                f" release file {metadata_sizes[path][0][1]}"
                            )

                        if any(
                            hash_sum != s[0]
                            for s in metadata_hashes.get(path, {}).get(hash_type, [])
                        ):
                            raise InvalidReleaseFilesException(
                                f"Hashsum of type {hash_type} of file {path} in release"
                                f" file {release_file_relative_path} differs from"
                                " hashsum in release file"
                                f" {metadata_hashes[path][hash_type][0][1]}"
                            )

                        metadata_sizes.setdefault(path, []).append(
                            (size, release_file_relative_path)
                        )
                        metadata_hashes.setdefault(path, {}).setdefault(
                            hash_type, []
                        ).append((hash_sum, release_file_relative_path))

        if not release_files_exists:
            raise InvalidReleaseFilesException("No release files were found")

    @property
    def release_files(self) -> Sequence[Path]:
        return [
            path
            for _, paths in self.release_files_per_metadata.items()
            for path in paths
        ]

    @abstractmethod
    def _metadata_file_allowed(
        self, metadata: BaseRepositoryMetadata, file_path: Path
    ) -> bool: ...

    @abstractmethod
    def get_by_hash_policy(self, metadata: BaseRepositoryMetadata) -> ByHash: ...

    @property
    @abstractmethod
    def is_source_enabled(self) -> bool: ...

    @property
    @abstractmethod
    def is_binaries_enabled(self) -> bool: ...

    @property
    @abstractmethod
    def release_files_per_metadata(
        self,
    ) -> dict[BaseRepositoryMetadata, Sequence[Path]]: ...

    @property
    @abstractmethod
    def sources_files(self) -> Sequence[Path]: ...

    @property
    @abstractmethod
    def packages_files(self) -> Sequence[Path]: ...


@dataclass
class Repository(BaseRepository):
    class Codenames(dict[str, Codename]):
        def get_codename(self, codename: str) -> Codename:
            if codename not in self:
                raise RuntimeError(f"Requested codename was not found: {codename}")

            return self[codename]

        def __str__(self) -> str:
            return str([c for c in self])

    DISTS = Path("dists")

    codenames: Codenames

    def _metadata_file_allowed(
        self, metadata: BaseRepositoryMetadata, file_path: Path
    ) -> bool:
        codename = self.codenames.get_codename(metadata.as_string())
        file_path_str = str(file_path)

        # Skip source metadata if not needed
        if not codename.should_mirror_source() and (
            "/source/" in file_path_str or file_path.name.startswith("Contents-source")
        ):
            return False

        # Skip binary metadata if not needed
        if not codename.should_mirror_binaries() and any(
            part in file_path_str for part in ("/binary-", "/cnf/", "/dep11/", "/i18n/")
        ):
            return False

        # Skip redundand components
        components_split = min(file_path_str.count("/"), 2)
        if components_split >= 1:
            file_component = file_path_str.rsplit("/", maxsplit=components_split)[0]

            if not any(
                file_component == component.name
                for component in codename.components.values()
            ):
                return False

            if (
                "/binary-" in file_path_str
                and "source" not in file_path_str
                and (
                    not codename.should_mirror_binaries()
                    or not any(
                        arch in file_path_str
                        for arch in itertools.chain(
                            codename.components[file_component].arches, ["-all"]
                        )
                    )
                )
            ):
                return False

        all_arches = set(
            arch
            for component in codename.components.values()
            for arch in component.arches
        )
        if all_arches:
            all_arches.add("all")

        if (
            any(
                file_path.name.startswith(suffix)
                for suffix in ("Commands-", "Components-", "Contents-")
            )
            and "source" not in file_path.name
            and not any(arch in file_path.name for arch in all_arches)
        ):
            return False

        if (
            "Contents-" in file_path_str
            and ".diff" in file_path_str
            and not any(arch in file_path.name for arch in all_arches)
        ):
            return False

        # Allow any metadata not explicitly disallowed
        return True

    @property
    def is_source_enabled(self) -> bool:
        return any(c.should_mirror_source() for c in self.codenames.values())

    @property
    def is_binaries_enabled(self) -> bool:
        return any(c.should_mirror_binaries() for c in self.codenames.values())

    @property
    def release_files_per_metadata(
        self,
    ) -> dict[BaseRepositoryMetadata, Sequence[Path]]:
        return {
            codename: [
                self.DISTS / codename.as_string() / file for file in self.RELEASE_FILES
            ]
            for codename in self.codenames.values()
        }

    @property
    def sources_files(self) -> Sequence[Path]:
        return [
            self.DISTS / codename.as_string() / component.name / "source" / "Sources"
            for codename in self.codenames.values()
            for component in codename.components.values()
        ]

    @property
    def packages_files(self) -> Sequence[Path]:
        return [
            path
            for path in itertools.chain.from_iterable(
                itertools.chain(
                    (
                        self.DISTS
                        / codename.as_string()
                        / component.name
                        / f"binary-{arch}"
                        / "Packages"
                        for arch in component.arches
                    ),
                    [
                        self.DISTS
                        / codename.as_string()
                        / component.name
                        / "binary-all"
                        / "Packages"
                    ],
                )
                for codename in self.codenames.values()
                for component in codename.components.values()
            )
        ]

    def get_by_hash_policy(self, metadata: BaseRepositoryMetadata) -> ByHash:
        return self.codenames.get_codename(metadata.as_string()).by_hash

    def __str__(self) -> str:
        return (
            f"{self.url}, codenames: {self.codenames}, mirror_path: {self.mirror_path}"
        )


@dataclass
class FlatRepository(BaseRepository):
    class FlatDirectories(dict[Path, FlatDirectory]):
        def get_directory(self, directory: Path) -> FlatDirectory:
            if directory not in self:
                raise RuntimeError(f"Requested directory was not found: {directory}")

            return self[directory]

        def __str__(self) -> str:
            return str([d.as_string() for d in self.values()])

    directories: FlatDirectories

    def _metadata_file_allowed(
        self, metadata: BaseRepositoryMetadata, file_path: Path
    ) -> bool:
        directory = self.directories.get_directory(metadata.as_path())

        if not directory.mirror_source and (
            any(
                str(file_path) == f"Sources{suffix}"
                for suffix in self.ALL_INDEX_SUFFIXES
            )
        ):
            return False

        if not directory.mirror_binaries and (
            any(
                str(file_path) == f"Packages{suffix}"
                for suffix in self.ALL_INDEX_SUFFIXES
            )
        ):
            return False

        return True

    @property
    def is_source_enabled(self) -> bool:
        return any(d.mirror_source for d in self.directories.values())

    @property
    def is_binaries_enabled(self) -> bool:
        return any(d.mirror_binaries for d in self.directories.values())

    @property
    def release_files_per_metadata(
        self,
    ) -> dict[BaseRepositoryMetadata, Sequence[Path]]:
        return {
            directory: [directory.as_path() / file for file in self.RELEASE_FILES]
            for directory in self.directories.values()
        }

    @property
    def sources_files(self) -> Sequence[Path]:
        return [
            directory.as_path() / "Sources" for directory in self.directories.values()
        ]

    @property
    def packages_files(self) -> Sequence[Path]:
        return [
            directory.as_path() / "Packages" for directory in self.directories.values()
        ]

    def get_by_hash_policy(self, metadata: BaseRepositoryMetadata) -> ByHash:
        return self.directories.get_directory(metadata.as_path()).by_hash

    def __str__(self) -> str:
        return (
            f"{self.url}, directories: {self.directories},"
            f" mirror_path: {self.mirror_path}"
        )
