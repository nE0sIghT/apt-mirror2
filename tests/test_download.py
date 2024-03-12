from pathlib import Path

from apt_mirror.download import DownloadFile, HashSum, HashType
from tests.base import BaseTest


class TestDownload(BaseTest):
    def test_download_file_size(self):
        file_path = Path("/tmp/t")
        file = DownloadFile.from_hashed_path(
            file_path, 1024, HashType.MD5, HashSum(HashType.MD5, ""), use_by_hash=True
        )
        file.add_compression_variant(file_path.with_suffix(".bz2"), 512)
        file.add_compression_variant(file_path.with_suffix(".xz"), 777)
        file.add_compression_variant(file_path.with_suffix(".gz"), 256)

        self.assertEqual(file.size, 777)
