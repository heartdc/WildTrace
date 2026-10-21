"""Tests for the WSL-backed real-library frame resolver.

The resolver shells out to WSL, so these tests pin the contract rather than the
distro: parsing, the landing rule, and the hook's return shape.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.poc_real import (_to_posix, describe, frame_lands, resolve_frame,
                            runtime_hook)

CHAIN = [
    {'function': 'std::__h::basic_string<char>::__init', 'file': '.../string', 'line': 1955},
    {'function': 'std::__h::basic_string<char>::basic_string', 'file': '.../string', 'line': 843},
    {'function': 'FfiUDMFSetProperties.cfi',
     'file': '.../unified_data_ffi.cpp', 'line': 134},
]

WRONG_CHAIN = [
    {'function': 'OHOS::UDMF::SetDataParameters',
     'file': '.../unified_data_parameter_parse.cpp', 'line': 0},
    {'function': 'FfiUDMFSetProperties.cfi',
     'file': '.../unified_data_ffi.cpp', 'line': 132},
]


class PathTests(unittest.TestCase):
    def test_windows_path_becomes_mnt(self):
        self.assertEqual(_to_posix('C:/Users/x/y.c'), '/mnt/c/Users/x/y.c')

    def test_backslashes_are_normalised(self):
        self.assertEqual(_to_posix('D:\\oh\\a.c'), '/mnt/d/oh/a.c')

    def test_posix_path_is_left_alone(self):
        self.assertEqual(_to_posix('/home/beichen/a.c'), '/home/beichen/a.c')


class LandingTests(unittest.TestCase):
    """The UDMF pair: same library, same exit code, only the frame differs."""

    def test_claimed_function_and_line_lands(self):
        self.assertTrue(frame_lands({'frames': CHAIN}, 'FfiUDMFSetProperties', 134))

    def test_claimed_function_wrong_line_does_not_land(self):
        self.assertFalse(frame_lands({'frames': WRONG_CHAIN}, 'FfiUDMFSetProperties', 134))

    def test_other_function_does_not_land(self):
        self.assertFalse(frame_lands({'frames': WRONG_CHAIN}, 'FfiUDMFGetProperties'))

    def test_function_only_comparison_ignores_line(self):
        self.assertTrue(frame_lands({'frames': WRONG_CHAIN}, 'FfiUDMFSetProperties'))

    def test_missing_chain_never_lands(self):
        self.assertFalse(frame_lands({'frames': []}, 'FfiUDMFSetProperties', 134))

    def test_no_expectation_lands(self):
        self.assertTrue(frame_lands({'frames': WRONG_CHAIN}, None))


class DescribeTests(unittest.TestCase):
    def test_crash_describes_the_chain(self):
        text = describe({'built': True, 'crashed': True, 'offset': '0x1718a',
                         'frames': CHAIN})
        self.assertIn('0x1718a', text)
        self.assertIn('unified_data_ffi.cpp:134', text)

    def test_no_crash_is_said_plainly(self):
        self.assertIn('without crashing', describe({'built': True, 'crashed': False,
                                                    'exit': 0}))

    def test_build_failure_carries_the_error(self):
        self.assertIn('did not build', describe({'built': False,
                                                 'build_error': "error: unknown type"}))


class RunnerTests(unittest.TestCase):
    def _run(self, stdout, returncode=0):
        class Completed:
            pass
        completed = Completed()
        completed.returncode = returncode
        completed.stdout = stdout
        completed.stderr = ''
        return completed

    def test_json_is_parsed_from_the_last_line(self):
        payload = json.dumps({'built': True, 'crashed': True, 'offset': '0x1718a',
                              'frames': CHAIN})
        with patch('ohvul.poc_real.subprocess.run',
                   return_value=self._run(f"noise\n{payload}")):
            data = resolve_frame(Path('draft.c'), 'lib/x.z.so',
                                 oh_root='/home/beichen/oh',
                                 build_output='/home/beichen/oh/out/x86_64_virt',
                                 evidence_dir=Path('/tmp/ev'))
        self.assertEqual(data['offset'], '0x1718a')
        self.assertTrue(data['crashed'])

    def test_soname_alias_is_passed_to_the_runner(self):
        """Generated drafts usually dlopen a guessed soname, so the runner has
        to be able to publish an alias of that name."""
        payload = json.dumps({'built': True, 'crashed': False, 'exit': 1})
        with patch('ohvul.poc_real.subprocess.run',
                   return_value=self._run(payload)) as mocked:
            resolve_frame(Path('draft.c'), 'lib/x.z.so', oh_root='/oh',
                          build_output='/out', soname_alias='libguessed.z.so')
        self.assertEqual(mocked.call_args[0][0][-1], 'libguessed.z.so')

    def test_unparsable_output_raises(self):
        with patch('ohvul.poc_real.subprocess.run', return_value=self._run('nope')), \
             self.assertRaises(Exception):
            resolve_frame(Path('draft.c'), 'lib/x.z.so', oh_root='/oh',
                          build_output='/out')

    def test_wsl_failure_is_reported(self):
        with patch('ohvul.poc_real.subprocess.run',
                   return_value=self._run('', returncode=126)), \
             self.assertRaises(Exception):
            resolve_frame(Path('draft.c'), 'lib/x.z.so', oh_root='/oh',
                          build_output='/out')


class HookTests(unittest.TestCase):
    """The hook is what llm_poc calls; its note is what the model gets back."""

    def _hook(self, data):
        # a temp dir, so a test never leaves a draft behind in the tree
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        with patch('ohvul.poc_real.resolve_frame', return_value=data) as mocked:
            hook = runtime_hook('distributeddatamgr/udmf/libcj_unified_data_channel_ffi.z.so',
                                oh_root='/home/beichen/oh',
                                build_output='/home/beichen/oh/out/x86_64_virt',
                                workdir=Path(scratch.name))
            result = hook('int main(void){return 0;}',
                          {'function': 'FfiUDMFSetProperties', 'line': 134})
        return result, mocked

    def test_landed_crash_is_accepted(self):
        (landed, note), _ = self._hook({'built': True, 'crashed': True,
                                        'offset': '0x1718a', 'frames': CHAIN})
        self.assertTrue(landed)
        self.assertIn('landed', note)

    def test_crash_elsewhere_is_refused_with_the_frame(self):
        (landed, note), _ = self._hook({'built': True, 'crashed': True,
                                        'offset': '0x16e5d', 'frames': WRONG_CHAIN})
        self.assertFalse(landed)
        self.assertTrue(note.startswith('crash_elsewhere'))
        self.assertIn('SetDataParameters', note)

    def test_no_crash_is_refused_as_no_crash(self):
        (landed, note), _ = self._hook({'built': True, 'crashed': False, 'exit': 0})
        self.assertFalse(landed)
        self.assertTrue(note.startswith('no_crash'))

    def test_draft_is_written_before_the_run(self):
        (_, _), mocked = self._hook({'built': True, 'crashed': True, 'frames': CHAIN})
        client = mocked.call_args[0][0]
        self.assertTrue(Path(client).is_file())
        self.assertIn('int main', Path(client).read_text(encoding='utf-8'))
        Path(client).unlink()


if __name__ == '__main__':
    unittest.main()
