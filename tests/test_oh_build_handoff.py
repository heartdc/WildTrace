"""Exercise build handoff scripts on disposable graphs and dummy .so files."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.oh_build.sweep_v3 import choose, rules, sweep

SCRIPT = Path(__file__).resolve().parents[1] / 'tools/oh_build/fix_rust_std2.sh'


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.output = self.base / 'output'
        self.output.mkdir()
        self.graph = self.output / 'build.ninja'

    def test_bindings_are_part_of_identity(self):
        self.graph.write_text('build x: phony\n  pool = one\nbuild x: phony\n  pool = two\n')
        with self.assertRaisesRegex(ValueError, 'UNHANDLED'):
            choose(rules(self.output, 'x'), 'x', self.output, [])

    def test_preferred_file_is_explicit(self):
        self.graph.write_text('build x: phony first\n')
        (self.output / 'toolchain.ninja').write_text('build x: phony second\n')
        hits = rules(self.output, 'x')
        with self.assertRaises(ValueError): choose(hits, 'x', self.output, [])
        removed, reason = choose(hits, 'x', self.output, ['toolchain.ninja'])
        self.assertEqual(removed[0], self.graph)
        self.assertEqual(reason, 'explicit-preferred-file')

    def test_continuations_are_not_partially_deleted(self):
        self.graph.write_text('build x: phony $\n  y\nbuild x: phony\n')
        with self.assertRaises(ValueError): rules(self.output, 'x')

    @unittest.skipUnless(shutil.which('ninja'), 'Ninja required')
    def test_real_ninja_dry_run_apply_backup_and_second_run(self):
        original = b'build x: phony\nbuild x: phony\nbuild all: phony x\n'
        self.graph.write_bytes(original)
        backup = self.base / 'backup'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sweep(self.output, shutil.which('ninja'), 'all'), 2)
            self.assertEqual(self.graph.read_bytes(), original)
            self.assertEqual(sweep(self.output, shutil.which('ninja'), 'all', True, backup), 0)
            self.assertEqual(sweep(self.output, shutil.which('ninja'), 'all'), 0)
        self.assertEqual((backup / 'build.ninja').read_bytes(), original)
        self.assertEqual(self.graph.read_text().count('build x:'), 1)

    @unittest.skipUnless(shutil.which('ninja'), 'Ninja required')
    def test_unknown_target_is_failure_not_graph_clean(self):
        self.graph.write_text('build x: phony\n')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sweep(self.output, shutil.which('ninja'), 'missing'), 1)

    @unittest.skipUnless(shutil.which('ninja'), 'Ninja required')
    def test_self_stamp_removed_with_real_ninja(self):
        self.graph.write_text('rule stamp\n  command = touch $out\nbuild x: phony\nbuild x: stamp x\nbuild all: phony x\n')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sweep(self.output, shutil.which('ninja'), 'all', True, self.base / 'backup'), 0)
        self.assertNotIn('build x: stamp x', self.graph.read_text())


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux/bash required')
class RustStageTests(unittest.TestCase):
    def test_copy_replaces_symlink_without_touching_target_and_keeps_backup(self):
        with tempfile.TemporaryDirectory(prefix='oh handoff ') as directory:
            base = Path(directory)
            source = base / 'source'
            rust = source / 'rust libs'
            rust.mkdir(parents=True)
            (rust / 'real-library').write_bytes(b'new-library')
            (rust / 'libstd.dylib.so').symlink_to('real-library')
            output = base / 'output'
            destination = output / 'obj/third_party/musl/usr/lib/x86_64-linux-ohos'
            destination.mkdir(parents=True)
            outside = base / 'old-library'
            outside.write_bytes(b'old-library')
            (destination / 'libstd.dylib.so').symlink_to(outside)
            backup = base / 'backup'
            env = {**os.environ, 'RUST_LIB_DIR': str(rust)}
            command = ['bash', str(SCRIPT), str(source), str(output)]
            check = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertTrue((destination / 'libstd.dylib.so').is_symlink())
            result = subprocess.run(command + ['--apply', str(backup)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((destination / 'libstd.dylib.so').read_bytes(), b'new-library')
            self.assertFalse((destination / 'libstd.dylib.so').is_symlink())
            self.assertEqual(outside.read_bytes(), b'old-library')
            self.assertTrue((backup / 'original/libstd.dylib.so').is_symlink())
            again = subprocess.run(command + ['--apply', str(backup)], env=env, capture_output=True)
            self.assertNotEqual(again.returncode, 0)
            # Restore the original directory entry from the backup.
            (destination / 'libstd.dylib.so').unlink()
            shutil.copy2(backup / 'original/libstd.dylib.so', destination / 'libstd.dylib.so', follow_symlinks=False)
            self.assertEqual((destination / 'libstd.dylib.so').read_bytes(), b'old-library')

    def test_missing_runtime_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            result = subprocess.run(['bash', str(SCRIPT), str(p), str(p)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
