# SPDX-License-Identifer: GPL-3.0-or-later

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class HashType(Enum):
    SHA512 = "SHA512"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5Sum"


@dataclass
class HashSum:
    type: HashType
    hash: str


class FileCompression(Enum):
    XZ = "xz"
    GZ = "gz"
    BZ2 = "bz2"
    NONE = None

    @staticmethod
    def all_compressed() -> Iterable["FileCompression"]:
        return (
            compression
            for compression in FileCompression
            if compression != FileCompression.NONE
        )

    @staticmethod
    def all_compressed_extensions() -> Iterable[str]:
        return (
            compression.file_extension
            for compression in FileCompression.all_compressed()
        )

    @property
    def file_extension(self) -> str:
        if self.value:
            return f".{self.value}"

        return ""


@dataclass
class DownloadFileCompressionVariant:
    path: Path
    compression: FileCompression
    size: int
    hashes: dict[HashType, HashSum]
    use_by_hash: bool

    def _get_hashed_path(self, hash_type: HashType):
        return (
            self.path.parent / "by-hash" / hash_type.value / self.hashes[hash_type].hash
        )

    def get_source_path(self) -> Path:
        if self.use_by_hash:
            for hash_type in HashType:
                if hash_type in self.hashes:
                    return self._get_hashed_path(hash_type)

        return self.path

    def get_all_paths(self) -> Sequence[Path]:
        paths: list[Path] = []

        if not self.use_by_hash:
            paths.append(self.path)

        if self.use_by_hash:
            paths += [self._get_hashed_path(hash_type) for hash_type in self.hashes]

        if self.use_by_hash:
            paths.append(self.path)

        return paths


@dataclass
class DownloadFile:
    path: Path
    compression_variants: dict[FileCompression, DownloadFileCompressionVariant] = field(
        default_factory=lambda: {}
    )
    check_size: bool = False
    ignore_errors: bool = False
    ignore_missing: bool = False

    @staticmethod
    def uncompressed_path(path: Path):
        if path.suffix in FileCompression.all_compressed_extensions():
            return path.with_suffix("")

        return path

    @classmethod
    def from_path(
        cls, path: Path, check_size: bool = False, ignore_missing: bool = False
    ):
        return cls(path=path, check_size=check_size, ignore_missing=ignore_missing)

    @classmethod
    def from_hashed_path(
        cls,
        path: Path,
        size: int,
        hash_type: HashType,
        hash_sum: HashSum,
        use_by_hash: bool,
    ):
        download_file = DownloadFile.from_path(cls.uncompressed_path(path))
        download_file.add_compression_variant(
            path=path,
            size=size,
            hash_type=hash_type,
            hash_sum=hash_sum,
            use_by_hash=use_by_hash,
        )

        return download_file

    def __post_init__(self):
        if not self.compression_variants:
            self.add_compression_variant(self.path, size=0)

    def add_compression_variant(
        self,
        path: Path,
        size: int,
        hash_type: HashType | None = None,
        hash_sum: HashSum | None = None,
        use_by_hash: bool = False,
    ):
        hashes: dict[HashType, HashSum] = {}
        if hash_type and hash_sum:
            hashes[hash_type] = hash_sum

        compression = FileCompression.NONE
        for _compression in FileCompression:
            if _compression.file_extension.lower() == path.suffix:
                compression = _compression
                break

        if compression == FileCompression.NONE:
            self.path = path

        compression_variant = self.compression_variants.setdefault(
            compression,
            DownloadFileCompressionVariant(
                path=path,
                compression=compression,
                size=size,
                hashes=hashes,
                use_by_hash=use_by_hash,
            ),
        )

        compression_variant.path = path
        compression_variant.size = size
        compression_variant.use_by_hash = use_by_hash
        compression_variant.hashes.update(hashes)

    def iter_variants(self):
        for compression in FileCompression:
            if compression in self.compression_variants:
                yield self.compression_variants[compression]

    @property
    def size(self):
        for compression in FileCompression:
            if compression not in self.compression_variants:
                continue

            return self.compression_variants[compression].size

        raise RuntimeError(f"{self.__class__.__name__} {self} is empty")

    def __hash__(self) -> int:
        return hash(self.path)

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f"DownloadFile: path: {self.path}, size: {self.size}"
