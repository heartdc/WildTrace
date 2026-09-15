"""Containment checks retained across the parallel portable-path change."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ohvul.engine_adapter import _normalize_engine_path


class PortablePathBoundaryTests(unittest.TestCase):
    def test_windows_and_wsl_parent_segments_are_rejected(self):
        root = Path('C:/audit-root')
        for value in ('C:/audit-root/../outside.c', '/mnt/c/audit-root/../outside.c',
                      'C:/audit-root/sub/../../outside.c'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _normalize_engine_path(value, root)

    def test_valid_portable_locations_still_normalize(self):
        root = Path('C:/audit-root')
        for value in ('C:/audit-root/src/a.c', '/mnt/c/audit-root/src/a.c'):
            self.assertEqual(_normalize_engine_path(value, root), 'src/a.c')

    @unittest.skipUnless(os.name == 'nt', 'native Windows filesystem containment')
    def test_native_windows_resolution_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent/'source'
            root.mkdir()
            path = root/'linked.c'
            original = Path.resolve
            def resolved(value, *args, **kwargs):
                if str(value).casefold() == str(path).casefold():
                    return parent/'outside.c'
                return original(value, *args, **kwargs)
            with patch.object(Path, 'resolve', autospec=True, side_effect=resolved):
                with self.assertRaises(ValueError):
                    _normalize_engine_path(str(path), root)


if __name__ == '__main__':
    unittest.main()
