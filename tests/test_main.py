import sys
from tempfile import NamedTemporaryFile
from unittest.mock import patch

from apt_mirror.apt_mirror import get_config_file
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
