import errno
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import patch

from apt_mirror.apt_mirror import APTMirror, get_config_file, is_alternative_binary_path
from apt_mirror.config import Config
from tests.base import BaseTest


class TestMain(BaseTest):
    def test_config_file_argument(self):
        with (
            NamedTemporaryFile() as tmp_file,
            NamedTemporaryFile() as tmp_file2,
            patch.object(Config, "DEFAULT_CONFIGFILE", tmp_file.name),
            patch.object(Config, "DEFAULT_CONFIGFILE2", tmp_file2.name),
        ):
            with patch.object(sys, "argv", ["apt-mirror"]):
                self.assertEqual(str(get_config_file()), Config.DEFAULT_CONFIGFILE)

            with patch.object(sys, "argv", ["apt-mirror2"]):
                self.assertEqual(str(get_config_file()), Config.DEFAULT_CONFIGFILE2)

            with (
                patch.object(sys, "argv", ["apt-mirror2", "/~~~nonexistent"]),
                self.assertRaises(SystemExit),
            ):
                self.assertEqual(str(get_config_file()), Config.DEFAULT_CONFIGFILE)

        with (
            patch.object(Config, "DEFAULT_CONFIGFILE2", "/~~~nonexistent"),
            patch.object(sys, "argv", ["apt-mirror2"]),
            self.assertRaises(SystemExit),
        ):
            self.assertEqual(str(get_config_file()), Config.DEFAULT_CONFIGFILE2)

    def test_alternative_path(self):
        with patch.object(sys, "argv", ["apt-mirror"]):
            self.assertFalse(is_alternative_binary_path())

        with patch.object(sys, "argv", ["apt-mirror3"]):
            self.assertFalse(is_alternative_binary_path())

        with patch.object(sys, "argv", ["apt-mirror2"]):
            self.assertTrue(is_alternative_binary_path())

    def test_alternative_config_base_path(self):
        with NamedTemporaryFile() as tmp_file:
            config = Config(Path(tmp_file.name), Config.DEFAULT_BASE_PATH)
            self.assertEqual(config.base_path, Path(Config.DEFAULT_BASE_PATH))

            config = Config(Path(tmp_file.name), Config.DEFAULT_BASE_PATH2)
            self.assertEqual(config.base_path, Path(Config.DEFAULT_BASE_PATH2))

    def test_lock_exception(self):
        with TemporaryDirectory() as tempdir:
            config_path = Path(tempdir) / "mirror.list"
            config_path.touch()
            config = Config(config_file=config_path, default_base_path=tempdir)
            config.create_working_directories()
            apt_mirror = APTMirror(config)

            with self.assertRaises(PermissionError), apt_mirror.lock():
                raise PermissionError(errno.EPERM, "Operation not permitted")
