
import asyncio
import contextlib
import hashlib
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Mock external dependencies that might be missing in test env
try:
    import aiolimiter  # noqa: F401
except ImportError:
    sys.modules["aiolimiter"] = MagicMock()

from apt_mirror.download.download_file import DownloadFile, HashSum, HashType
from apt_mirror.download.downloader import Downloader, DownloaderSettings


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
        self.assertEqual(
            downloader._hash_mismatch_count, 0, "Mismatch count should be 0 for match"
        )

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
        self.assertEqual(
            downloader._hash_mismatch_count, 1, "Mismatch count should increment"
        )

        # Test Config Off
        downloader._settings.check_local_hash = False
        result_off = await downloader._check_hash(file_path, variants)
        self.assertFalse(result_off, "Should return False when config is off")

    def test_self_healing(self):
        asyncio.run(self._test_self_healing_logic())

    async def _test_self_healing_logic(self):
        # Setup: Two paths for the same file (variant).
        # Path 1: "main.deb" (Missing)
        # Path 2: "backup.deb" (Exists and Valid)

        main_path = self.tmp_dir / "main.deb"
        backup_path = self.tmp_dir / "backup.deb"

        content = b"self-healing-content"
        expected_hash = hashlib.sha256(content).hexdigest()

        # Create backup file only
        with open(backup_path, "wb") as f:
            f.write(content)

        # Ensure main file is missing
        if main_path.exists():
            main_path.unlink()

        # Mock Settings
        settings = MagicMock(spec=DownloaderSettings)
        settings.check_local_hash = True
        settings.target_root_path = self.tmp_dir
        settings.url = "http://example.com"
        settings.semaphore = asyncio.Semaphore(1)
        # Mock aiofile factory to support open
        # (needed if download triggers,
        # but we expect it NOT to trigger network download)
        settings.aiofile_factory = MagicMock()

        # Mock Downloader
        @contextlib.asynccontextmanager
        async def mock_stream(source_path):
             yield MagicMock()

        class TestDownloader(Downloader):
            def __post_init__(self):
                 self._log = MagicMock()

            def stream(self, source_path):
                return mock_stream(source_path)

        downloader = TestDownloader(settings=settings)

        # Create DownloadFile with one variant that has multiple paths
        download_file = DownloadFile.from_path(Path("main.deb"))

        # We need to inject a variant that returns multiple paths.
        # Since DownloadFile constructs variants internally,
        # we can construct one manually or mock it.
        # Let's mock the variant to return two paths.

        variant = MagicMock()
        variant.size = len(content)
        variant.hashes = {HashType.SHA256: HashSum(HashType.SHA256, expected_hash)}
        variant.get_all_paths.return_value = [Path("main.deb"), Path("backup.deb")]

        # Inject this variant into download_file
        # DownloadFile.iter_variants yields from self.compression_variants.values()
        download_file.iter_variants = MagicMock(return_value=[variant])

        # Execute download_file
        await downloader.download_file(download_file)

        # Verify
        # 1. main.deb should now exist (restored from backup.deb)
        self.assertTrue(main_path.exists(), "Main path should be restored")
        with open(main_path, "rb") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, content, "Restored content should match")

        # 2. Log should mention self-healing
        downloader._log.info.assert_called()
        log_args = [call.args[0] for call in downloader._log.info.call_args_list]
        self.assertTrue(
            any("Self-healed" in arg for arg in log_args),
            f"Log should contain 'Self-healed', got: {log_args}",
        )

        # 3. Stats should prevent re-download
        self.assertEqual(downloader._unmodified_count, 1)
        self.assertEqual(downloader._downloaded_count, 0)
