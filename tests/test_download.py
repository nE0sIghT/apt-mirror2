from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from apt_mirror.download import DownloadFile, HashSum, HashType
from apt_mirror.download.slow_rate_protector import SlowRateException, SlowRateProtector
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

    def test_slow_rate_protector(self):
        with patch(f"{SlowRateProtector.__module__}.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 0, 0)

            protector = SlowRateProtector("test", 60, 100)
            protector.rate(1)

            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 0, 59)
            protector.rate(1)

            mock_datetime.now.return_value = datetime(2024, 1, 1, 0, 1, 0)
            with self.assertRaises(SlowRateException):
                protector.rate(1)

            with self.assertRaises(SlowRateException):
                protector.rate(100 * 60 - 4)

            protector.rate(1)
