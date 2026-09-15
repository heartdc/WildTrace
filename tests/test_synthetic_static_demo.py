"""Test demo filesystem boundaries without invoking Git or any analyzer."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'synthetic_demo_test_module', Path(__file__).resolve().parents[1] / 'tools/synthetic_static_demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class SyntheticDemoBoundaryTests(unittest.TestCase):
    def test_git_metadata_output_is_rejected_before_any_write_or_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.git').mkdir()
            output = root / '.git' / 'demo'
            with patch.object(demo.subprocess, 'run') as process:
                with self.assertRaisesRegex(ValueError, 'Git metadata'):
                    demo.run_demo(output)
            process.assert_not_called()
            self.assertFalse(output.exists())

    def test_existing_output_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / 'keep.txt'
            sentinel.write_text('preserve')
            with patch.object(demo.subprocess, 'run') as process:
                with self.assertRaises(FileExistsError):
                    demo.run_demo(root)
            process.assert_not_called()
            self.assertEqual(sentinel.read_text(), 'preserve')

    def test_linked_output_parent_is_rejected_without_process(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / 'linked'
            output = parent / 'demo'
            with patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda p: p == parent), \
                    patch.object(demo.subprocess, 'run') as process:
                with self.assertRaisesRegex(ValueError, 'linked paths'):
                    demo.run_demo(output)
            process.assert_not_called()
            self.assertFalse(parent.exists())


if __name__ == '__main__':
    unittest.main()
