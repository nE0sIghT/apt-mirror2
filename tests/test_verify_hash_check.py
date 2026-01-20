
import asyncio
import hashlib
import shutil
import unittest
from pathlib import Path
from unittest.mock import MagicMock
import contextlib

from apt_mirror.download.downloader import Downloader, DownloaderSettings
from apt_mirror.download.download_file import DownloadFile, HashType, HashSum

class TestHashCheck(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path("./tmp_test_hash_check")
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir)
        self.tmp_dir.mkdir(exist_ok=True)
        
    def tearDown(self):
        if self.tmp_dir.exists():
           shutil.rmtree(self.tmp_dir)
           
    def test_check_hash_async(self):
        asyncio.run(self._test_check_hash_logic())

    async def _test_check_hash_logic(self):
        file_path = self.tmp_dir / "test_file"
        content = b"test content"
        with open(file_path, "wb") as f:
            f.write(content)
            
        expected_hash = hashlib.sha256(content).hexdigest()
        
        # Mock settings
        settings = MagicMock(spec=DownloaderSettings)
        settings.check_local_hash = True
        settings.target_root_path = self.tmp_dir
        settings.url = "http://example.com"
        
        @contextlib.asynccontextmanager
        async def mock_stream(source_path):
             yield MagicMock()

        class TestDownloader(Downloader):
            def __post_init__(self):
                 self._log = MagicMock()
            
            def stream(self, source_path):
                return mock_stream(source_path)

        downloader = TestDownloader(settings=settings)
        
        # Create DownloadFile
        download_file = DownloadFile.from_path(Path("test_file"))
        download_file.add_compression_variant(
            Path("test_file"),
            size=len(content),
            hash_type=HashType.SHA256,
            hash_sum=HashSum(type=HashType.SHA256, hash=expected_hash)
        )
        
        expected_md5 = hashlib.md5(content).hexdigest()
        download_file.add_compression_variant(
            Path("test_file"),
            size=len(content),
            hash_type=HashType.MD5,
            hash_sum=HashSum(type=HashType.MD5, hash=expected_md5)
        )
        
        variants = list(download_file.iter_variants())
        
        # Test Correct Hash
        downloader._hash_mismatch_count = 0
        result = await downloader._check_hash(file_path, variants)
        self.assertTrue(result, "Should return True for matching hash")
        self.assertEqual(downloader._hash_mismatch_count, 0, "Mismatch count should be 0 for match")
        
        # Test Mismatch
        wrong_hash = "a" * 64
        download_file_wrong = DownloadFile.from_path(Path("test_file"))
        download_file_wrong.add_compression_variant(
            Path("test_file"),
            size=len(content),
            hash_type=HashType.SHA256,
            hash_sum=HashSum(type=HashType.SHA256, hash=wrong_hash)
        )
        variants_wrong = list(download_file_wrong.iter_variants())
        
        downloader._hash_mismatch_count = 0
        result_wrong = await downloader._check_hash(file_path, variants_wrong)
        self.assertFalse(result_wrong, "Should return False for mismatching hash")
        self.assertEqual(downloader._hash_mismatch_count, 1, "Mismatch count should increment")

        # Test Config Off
        downloader._settings.check_local_hash = False
        result_off = await downloader._check_hash(file_path, variants)
        self.assertFalse(result_off, "Should return False when config is off")
